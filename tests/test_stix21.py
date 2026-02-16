"""Tests specific to STIX 2.1 bundles."""

from stix2nx import stix_to_graph


def test_stix21_loads(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert len(G.nodes) >= 6  # 6 SDOs


def test_infrastructure_node(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert "infrastructure--1" in G.nodes
    inf = G.nodes["infrastructure--1"]
    assert inf["type"] == "infrastructure"
    assert inf["name"] == "C2 Server"
    assert isinstance(inf["infrastructure_types"], list)


def test_location_node(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert "location--1" in G.nodes
    loc = G.nodes["location--1"]
    assert loc["type"] == "location"
    assert loc["name"] == "Eastern Europe"
    assert loc["region"] == "eastern-europe"


def test_malware_analysis_node(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert "malware-analysis--1" in G.nodes
    ma = G.nodes["malware-analysis--1"]
    assert ma["type"] == "malware-analysis"
    assert ma["product"] == "CuckooSandbox"
    assert ma["result"] == "malicious"


def test_note_node(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert "note--1" in G.nodes
    note = G.nodes["note--1"]
    assert note["type"] == "note"
    assert note["content"] == "This actor is highly dangerous."


def test_opinion_node(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert "opinion--1" in G.nodes
    opinion = G.nodes["opinion--1"]
    assert opinion["type"] == "opinion"
    assert opinion["opinion"] == "strongly-agree"


def test_grouping_node(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert "grouping--1" in G.nodes
    grp = G.nodes["grouping--1"]
    assert grp["type"] == "grouping"
    assert grp["name"] == "Threat Cluster Alpha"
    assert isinstance(grp["object_refs"], list)
    assert len(grp["object_refs"]) == 2


def test_stix21_relationship(stix21_bundle):
    G = stix_to_graph([stix21_bundle])
    assert G.has_edge("infrastructure--1", "location--1")
    edges = list(G.edges("infrastructure--1", data=True))
    rel = [d for _, _, d in edges if d.get("relationship_type") == "located-at"]
    assert len(rel) == 1


def test_stix21_standalone_scos():
    """STIX 2.1 standalone SCOs handled correctly."""
    bundle = {
        "type": "bundle",
        "id": "bundle--sco21",
        "objects": [
            {
                "type": "ipv4-addr",
                "id": "ipv4-addr--21",
                "spec_version": "2.1",
                "value": "192.0.2.1",
            },
            {
                "type": "domain-name",
                "id": "domain-name--21",
                "spec_version": "2.1",
                "value": "test.example.com",
            },
        ],
    }
    G = stix_to_graph([bundle])
    assert "ipv4-addr--21" in G.nodes
    assert "domain-name--21" in G.nodes
    assert G.nodes["ipv4-addr--21"]["value"] == "192.0.2.1"
