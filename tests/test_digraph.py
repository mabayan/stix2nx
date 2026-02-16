"""Tests for DiGraph vs MultiDiGraph output."""

import networkx as nx

from stix2nx import stix_to_graph


def test_multidigraph_is_default(basic_bundle):
    G = stix_to_graph([basic_bundle])
    assert isinstance(G, nx.MultiDiGraph)


def test_digraph_output(basic_bundle):
    G = stix_to_graph([basic_bundle], graph_type="digraph")
    assert isinstance(G, nx.DiGraph)
    assert not isinstance(G, nx.MultiDiGraph)


def test_multidigraph_preserves_multiple_edges(multi_edge_bundle):
    G = stix_to_graph([multi_edge_bundle], graph_type="multidigraph")
    assert isinstance(G, nx.MultiDiGraph)
    edge_data = G["threat-actor--multi"]["malware--multi"]
    assert len(edge_data) == 2
    rel_types = {edge_data[k]["relationship_type"] for k in edge_data}
    assert rel_types == {"uses", "attributed-to"}


def test_digraph_collapses_multiple_edges(multi_edge_bundle):
    G = stix_to_graph([multi_edge_bundle], graph_type="digraph")
    assert isinstance(G, nx.DiGraph)
    assert G.has_edge("threat-actor--multi", "malware--multi")
    # DiGraph only stores one edge between any pair
    edge_data = G.edges["threat-actor--multi", "malware--multi"]
    assert "relationship_type" in edge_data


def test_same_node_set(multi_edge_bundle):
    G_multi = stix_to_graph([multi_edge_bundle], graph_type="multidigraph")
    G_di = stix_to_graph([multi_edge_bundle], graph_type="digraph")
    assert set(G_multi.nodes) == set(G_di.nodes)


def test_shortest_path_works_on_both(basic_bundle):
    G_multi = stix_to_graph([basic_bundle], graph_type="multidigraph")
    G_di = stix_to_graph([basic_bundle], graph_type="digraph")

    path_multi = nx.shortest_path(G_multi, "threat-actor--1", "malware--1")
    path_di = nx.shortest_path(G_di, "threat-actor--1", "malware--1")

    assert path_multi == ["threat-actor--1", "malware--1"]
    assert path_di == ["threat-actor--1", "malware--1"]


def test_invalid_graph_type(basic_bundle):
    import pytest

    with pytest.raises(ValueError, match="graph_type"):
        stix_to_graph([basic_bundle], graph_type="undirected")
