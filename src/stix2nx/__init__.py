"""stix2nx: Convert STIX cyber threat intelligence bundles to NetworkX graphs."""

from typing import Union

import networkx as nx

from .converter import convert_bundle
from .parsers import parse_source

__version__ = "0.1.0"


def stix_to_graph(
    source: Union[str, list[str], list[dict]],
    graph_type: str = "multidigraph",
    include_scos: bool = True,
) -> Union[nx.MultiDiGraph, nx.DiGraph]:
    """Convert STIX bundle(s) to a NetworkX graph.

    Args:
        source: STIX bundle source. One of:
            - str: file path (.json) or directory path
            - list[str]: list of JSON strings, each a STIX bundle
            - list[dict]: list of already-parsed STIX bundle dicts
        graph_type: Type of graph to create. "multidigraph" (default) allows
            multiple edges between the same node pair. "digraph" collapses
            multiple edges (last-write-wins).
        include_scos: Whether to include STIX Cyber-observable Objects as
            nodes. Default True.

    Returns:
        A NetworkX MultiDiGraph or DiGraph populated with STIX objects.

    Raises:
        ValueError: If source format is invalid, graph_type is unknown,
            or JSON parsing fails.
        FileNotFoundError: If a file or directory path doesn't exist.
    """
    if graph_type == "multidigraph":
        graph = nx.MultiDiGraph()
    elif graph_type == "digraph":
        graph = nx.DiGraph()
    else:
        raise ValueError(
            f"graph_type must be 'multidigraph' or 'digraph', got {graph_type!r}"
        )

    bundles = parse_source(source)

    for bundle in bundles:
        convert_bundle(graph, bundle, include_scos=include_scos)

    return graph
