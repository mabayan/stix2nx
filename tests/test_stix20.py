"""Tests specific to STIX 2.0 bundles."""

from stix2nx import stix_to_graph


def test_stix20_loads(stix20_bundle):
    G = stix_to_graph([stix20_bundle])
    assert "threat-actor--20" in G.nodes
    assert "malware--20" in G.nodes


def test_stix20_relationship(stix20_bundle):
    G = stix_to_graph([stix20_bundle])
    assert G.has_edge("threat-actor--20", "malware--20")


def test_stix20_embedded_scos_extracted(stix20_bundle):
    G = stix_to_graph([stix20_bundle], include_scos=True)
    # observed-data node should exist
    assert "observed-data--20" in G.nodes
    # Embedded SCOs should be extracted with synthetic IDs
    assert "observed-data--20--embedded-0" in G.nodes
    assert "observed-data--20--embedded-1" in G.nodes
    # Check their attributes
    ip_node = G.nodes["observed-data--20--embedded-0"]
    assert ip_node["type"] == "ipv4-addr"
    assert ip_node["value"] == "203.0.113.50"
    domain_node = G.nodes["observed-data--20--embedded-1"]
    assert domain_node["type"] == "domain-name"
    assert domain_node["value"] == "legacy.example.com"


def test_stix20_embedded_scos_excluded(stix20_bundle):
    G = stix_to_graph([stix20_bundle], include_scos=False)
    # observed-data SDO should still exist
    assert "observed-data--20" in G.nodes
    # But embedded SCOs should NOT be extracted
    assert "observed-data--20--embedded-0" not in G.nodes
    assert "observed-data--20--embedded-1" not in G.nodes


def test_stix20_no_newer_types(stix20_bundle):
    """STIX 2.0 bundles without infrastructure/location/etc work fine."""
    G = stix_to_graph([stix20_bundle])
    types = {d["type"] for _, d in G.nodes(data=True)}
    # Should not crash, just have the types that are present
    assert "threat-actor" in types
    assert "malware" in types


def test_stix20_node_attributes(stix20_bundle):
    G = stix_to_graph([stix20_bundle])
    ta = G.nodes["threat-actor--20"]
    assert ta["name"] == "Legacy Actor"
    assert isinstance(ta["labels"], list)
    assert ta["labels"] == ["criminal"]
