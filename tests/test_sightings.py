"""Tests for sighting node+edge creation."""

from stix2nx import stix_to_graph


def test_sighting_becomes_node(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    assert "sighting--full" in G.nodes
    assert "sighting--minimal" in G.nodes


def test_sighting_node_attributes(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    s = G.nodes["sighting--full"]
    assert s["type"] == "sighting"
    assert s["count"] == 3
    assert s["first_seen"] == "2023-06-01T00:00:00.000Z"
    assert s["last_seen"] == "2023-06-15T00:00:00.000Z"


def test_sighting_of_edge(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    edges = list(G.edges("sighting--full", data=True))
    sighting_of_edges = [
        (u, v, d) for u, v, d in edges if d.get("relationship_type") == "sighting_of"
    ]
    assert len(sighting_of_edges) == 1
    _, target, _ = sighting_of_edges[0]
    assert target == "indicator--sighted"


def test_where_sighted_edges(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    edges = list(G.edges("sighting--full", data=True))
    seen_by_edges = [
        (u, v, d) for u, v, d in edges if d.get("relationship_type") == "seen_by"
    ]
    assert len(seen_by_edges) == 1
    _, target, _ = seen_by_edges[0]
    assert target == "identity--org1"


def test_observed_data_edges(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    edges = list(G.edges("sighting--full", data=True))
    observed_edges = [
        (u, v, d) for u, v, d in edges if d.get("relationship_type") == "observed"
    ]
    assert len(observed_edges) == 1
    _, target, _ = observed_edges[0]
    assert target == "observed-data--1"


def test_sighting_all_refs(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    edges = list(G.edges("sighting--full", data=True))
    rel_types = {d.get("relationship_type") for _, _, d in edges}
    assert rel_types == {"sighting_of", "seen_by", "observed"}


def test_minimal_sighting(sighting_bundle):
    G = stix_to_graph([sighting_bundle])
    edges = list(G.edges("sighting--minimal", data=True))
    assert len(edges) == 1
    _, target, data = edges[0]
    assert target == "intrusion-set--sighted"
    assert data["relationship_type"] == "sighting_of"
