"""Unit tests for basic SDO-to-node and relationship-to-edge conversion."""

from stix2nx import stix_to_graph


def test_sdos_become_nodes(basic_bundle):
    G = stix_to_graph([basic_bundle])
    assert "threat-actor--1" in G.nodes
    assert "malware--1" in G.nodes
    assert "attack-pattern--1" in G.nodes


def test_node_ids_match_stix_ids(basic_bundle):
    G = stix_to_graph([basic_bundle])
    for node_id in G.nodes:
        assert G.nodes[node_id]["id"] == node_id


def test_node_attributes_correct(basic_bundle):
    G = stix_to_graph([basic_bundle])
    ta = G.nodes["threat-actor--1"]
    assert ta["type"] == "threat-actor"
    assert ta["name"] == "Evil Corp"
    assert ta["sophistication"] == "expert"
    assert ta["created"] == "2023-01-01T00:00:00.000Z"


def test_list_properties_remain_lists(basic_bundle):
    G = stix_to_graph([basic_bundle])
    ta = G.nodes["threat-actor--1"]
    assert isinstance(ta["aliases"], list)
    assert ta["aliases"] == ["BadGuys", "Villains"]
    assert isinstance(ta["threat_actor_types"], list)
    assert ta["threat_actor_types"] == ["criminal"]

    mal = G.nodes["malware--1"]
    assert isinstance(mal["malware_types"], list)
    assert mal["malware_types"] == ["trojan", "downloader"]


def test_all_properties_preserved(basic_bundle):
    G = stix_to_graph([basic_bundle])
    ap = G.nodes["attack-pattern--1"]
    assert "kill_chain_phases" in ap
    assert isinstance(ap["kill_chain_phases"], list)
    assert ap["kill_chain_phases"][0]["phase_name"] == "initial-access"


def test_relationships_become_edges(basic_bundle):
    G = stix_to_graph([basic_bundle])
    assert G.has_edge("threat-actor--1", "malware--1")
    assert G.has_edge("threat-actor--1", "attack-pattern--1")


def test_edge_attributes(basic_bundle):
    G = stix_to_graph([basic_bundle])
    edges = list(G.edges("threat-actor--1", data=True))
    rel_types = {d["relationship_type"] for _, _, d in edges}
    assert "uses" in rel_types

    for _, _, d in edges:
        assert "id" in d
        assert d["id"].startswith("relationship--")


def test_marking_definitions_excluded(marking_bundle):
    G = stix_to_graph([marking_bundle])
    assert "marking-definition--1" not in G.nodes
    assert "language-content--1" not in G.nodes
    assert "threat-actor--with-marking" in G.nodes


def test_empty_bundle(empty_bundle):
    G = stix_to_graph([empty_bundle])
    assert len(G.nodes) == 0
    assert len(G.edges) == 0


def test_nodes_only_bundle(nodes_only_bundle):
    G = stix_to_graph([nodes_only_bundle])
    assert len(G.nodes) == 2
    assert len(G.edges) == 0
    assert "threat-actor--solo" in G.nodes
    assert "malware--solo" in G.nodes


def test_json_string_input(basic_bundle_json):
    G = stix_to_graph([basic_bundle_json])
    assert len(G.nodes) == 3
    assert len(G.edges) == 2


def test_file_input(basic_bundle, tmp_path):
    import json

    file_path = tmp_path / "test.json"
    file_path.write_text(json.dumps(basic_bundle))
    G = stix_to_graph(str(file_path))
    assert len(G.nodes) == 3
    assert len(G.edges) == 2


def test_directory_input(basic_bundle, nodes_only_bundle, tmp_path):
    import json

    (tmp_path / "a.json").write_text(json.dumps(basic_bundle))
    (tmp_path / "b.json").write_text(json.dumps(nodes_only_bundle))
    G = stix_to_graph(str(tmp_path))
    # 3 from basic + 2 from nodes_only = 5
    assert len(G.nodes) == 5
