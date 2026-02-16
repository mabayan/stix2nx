"""Core conversion logic: STIX bundle dicts to NetworkX graph objects."""

import logging

import networkx as nx

from .utils import (
    extract_stix20_embedded_scos,
    is_relationship,
    is_sco,
    is_sdo,
    is_sighting,
    is_skippable,
)

logger = logging.getLogger(__name__)


def _obj_to_attrs(obj: dict) -> dict:
    """Convert a STIX object dict to a dict of NetworkX node/edge attributes.

    All properties are preserved. List-valued properties stay as Python lists.
    """
    attrs = {}
    for key, value in obj.items():
        if isinstance(value, list):
            attrs[key] = list(value)
        elif isinstance(value, dict):
            attrs[key] = dict(value)
        else:
            attrs[key] = value
    return attrs


def convert_bundle(
    graph: nx.MultiDiGraph | nx.DiGraph,
    bundle: dict,
    include_scos: bool = True,
) -> None:
    """Process a single STIX bundle dict into an existing NetworkX graph.

    SDOs become nodes, relationships become edges, sightings become nodes + edges.
    Marking definitions and language content are skipped.

    Args:
        graph: The NetworkX graph to populate (modified in place).
        bundle: A parsed STIX bundle dict.
        include_scos: Whether to include SCO objects as nodes.
    """
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        logger.warning("Bundle 'objects' field is not a list, skipping")
        return

    for obj in objects:
        if not isinstance(obj, dict):
            logger.warning(f"Skipping non-dict object in bundle: {type(obj).__name__}")
            continue

        obj_type = obj.get("type")
        obj_id = obj.get("id")

        if not obj_type:
            logger.warning(f"Skipping object with no 'type' field: {obj}")
            continue
        if not obj_id:
            if not is_skippable(obj):
                logger.warning(f"Skipping object with no 'id' field: {obj}")
            continue

        if is_skippable(obj):
            continue
        elif is_relationship(obj):
            _add_relationship(graph, obj)
        elif is_sighting(obj):
            _add_sighting(graph, obj)
        elif is_sdo(obj):
            _add_node(graph, obj)
            # Handle STIX 2.0 embedded SCOs in observed-data
            if obj_type == "observed-data" and include_scos:
                embedded_scos = extract_stix20_embedded_scos(obj)
                for sco in embedded_scos:
                    _add_node(graph, sco)
        elif is_sco(obj):
            if include_scos:
                _add_node(graph, obj)
        else:
            # Unknown type — treat as a node (could be custom object)
            logger.debug(f"Adding unknown object type as node: {obj_type}")
            _add_node(graph, obj)


def _add_node(graph: nx.MultiDiGraph | nx.DiGraph, obj: dict) -> None:
    """Add a STIX object as a node in the graph."""
    node_id = obj["id"]
    attrs = _obj_to_attrs(obj)
    graph.add_node(node_id, **attrs)


def _add_relationship(graph: nx.MultiDiGraph | nx.DiGraph, obj: dict) -> None:
    """Add a STIX relationship as a directed edge in the graph."""
    source_ref = obj.get("source_ref")
    target_ref = obj.get("target_ref")

    if not source_ref or not target_ref:
        logger.warning(
            f"Relationship {obj.get('id')} missing source_ref or target_ref, skipping"
        )
        return

    attrs = _obj_to_attrs(obj)
    # Remove source_ref and target_ref from edge attrs (they're encoded in the edge itself)
    attrs.pop("source_ref", None)
    attrs.pop("target_ref", None)
    attrs.pop("type", None)

    graph.add_edge(source_ref, target_ref, **attrs)


def _add_sighting(graph: nx.MultiDiGraph | nx.DiGraph, obj: dict) -> None:
    """Add a sighting as a node with edges to referenced objects.

    - The sighting itself becomes a node
    - sighting_of_ref → edge with relationship_type="sighting_of"
    - where_sighted_refs → edges with relationship_type="seen_by"
    - observed_data_refs → edges with relationship_type="observed"
    """
    node_id = obj["id"]
    attrs = _obj_to_attrs(obj)
    graph.add_node(node_id, **attrs)

    sighting_of = obj.get("sighting_of_ref")
    if sighting_of:
        graph.add_edge(node_id, sighting_of, relationship_type="sighting_of")

    for ref in obj.get("where_sighted_refs", []):
        graph.add_edge(node_id, ref, relationship_type="seen_by")

    for ref in obj.get("observed_data_refs", []):
        graph.add_edge(node_id, ref, relationship_type="observed")
