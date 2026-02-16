"""Tests for merging multiple bundles."""

from stix2nx import stix_to_graph


def test_merge_no_overlap(merge_bundle_a, merge_bundle_c):
    G = stix_to_graph([merge_bundle_a, merge_bundle_c])
    assert "threat-actor--merge-a" in G.nodes
    assert "malware--shared" in G.nodes
    assert "tool--merge-c" in G.nodes
    assert len(G.nodes) == 3


def test_merge_overlapping_nodes(merge_bundle_a, merge_bundle_b):
    G = stix_to_graph([merge_bundle_a, merge_bundle_b])
    # malware--shared should be deduplicated (later wins)
    shared = G.nodes["malware--shared"]
    assert shared["name"] == "Shared Malware v2"  # bundle_b overwrites
    assert shared["is_family"] is False  # bundle_b value
    # Both unique actors present
    assert "threat-actor--merge-a" in G.nodes
    assert "threat-actor--merge-b" in G.nodes


def test_merge_edges_accumulated(merge_bundle_a, merge_bundle_b):
    G = stix_to_graph([merge_bundle_a, merge_bundle_b], graph_type="multidigraph")
    # Both edges to malware--shared should exist
    edges_to_shared = [
        (u, v, d)
        for u, v, d in G.edges(data=True)
        if v == "malware--shared"
    ]
    assert len(edges_to_shared) == 2


def test_merge_three_bundles(merge_bundle_a, merge_bundle_b, merge_bundle_c):
    G = stix_to_graph([merge_bundle_a, merge_bundle_b, merge_bundle_c])
    assert "threat-actor--merge-a" in G.nodes
    assert "threat-actor--merge-b" in G.nodes
    assert "malware--shared" in G.nodes
    assert "tool--merge-c" in G.nodes


def test_merge_json_strings(merge_bundle_a, merge_bundle_b):
    import json

    json_a = json.dumps(merge_bundle_a)
    json_b = json.dumps(merge_bundle_b)
    G = stix_to_graph([json_a, json_b])
    assert "threat-actor--merge-a" in G.nodes
    assert "threat-actor--merge-b" in G.nodes
    assert "malware--shared" in G.nodes
