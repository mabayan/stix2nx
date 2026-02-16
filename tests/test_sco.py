"""Tests for SCO inclusion/exclusion."""

from stix2nx import stix_to_graph


def test_scos_included_by_default(sco_bundle):
    G = stix_to_graph([sco_bundle])
    assert "ipv4-addr--1" in G.nodes
    assert "domain-name--1" in G.nodes
    assert "file--1" in G.nodes
    assert "url--1" in G.nodes
    assert "email-addr--1" in G.nodes


def test_scos_excluded(sco_bundle):
    G = stix_to_graph([sco_bundle], include_scos=False)
    # SCOs without incoming relationships should not be in the graph
    assert "domain-name--1" not in G.nodes
    assert "file--1" not in G.nodes
    assert "url--1" not in G.nodes
    assert "email-addr--1" not in G.nodes
    # ipv4-addr--1 may exist as an auto-created stub from the relationship edge,
    # but it should NOT have SCO attributes (value, type, etc.)
    if "ipv4-addr--1" in G.nodes:
        assert "value" not in G.nodes["ipv4-addr--1"]
    # SDOs should still be present
    assert "indicator--1" in G.nodes


def test_sco_properties_mapped(sco_bundle):
    G = stix_to_graph([sco_bundle])

    ip = G.nodes["ipv4-addr--1"]
    assert ip["type"] == "ipv4-addr"
    assert ip["value"] == "198.51.100.1"

    domain = G.nodes["domain-name--1"]
    assert domain["value"] == "evil.example.com"

    url = G.nodes["url--1"]
    assert url["value"] == "https://evil.example.com/payload"

    email = G.nodes["email-addr--1"]
    assert email["value"] == "attacker@evil.example.com"


def test_file_sco_with_hashes(sco_bundle):
    G = stix_to_graph([sco_bundle])
    f = G.nodes["file--1"]
    assert f["name"] == "malware.exe"
    assert isinstance(f["hashes"], dict)
    assert "SHA-256" in f["hashes"]
    assert "MD5" in f["hashes"]
    assert f["size"] == 1024


def test_sco_relationship_preserved(sco_bundle):
    G = stix_to_graph([sco_bundle])
    assert G.has_edge("indicator--1", "ipv4-addr--1")
    edges = list(G.edges("indicator--1", data=True))
    assert any(d.get("relationship_type") == "based-on" for _, _, d in edges)


def test_sco_exclusion_does_not_affect_sdos(sco_bundle):
    G_with = stix_to_graph([sco_bundle], include_scos=True)
    G_without = stix_to_graph([sco_bundle], include_scos=False)
    # Indicator is an SDO, should be in both
    assert "indicator--1" in G_with.nodes
    assert "indicator--1" in G_without.nodes
