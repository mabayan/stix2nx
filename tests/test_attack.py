"""Integration test against MITRE ATT&CK STIX bundle.

Default: uses curated ~700KB subset checked into the repo.
With STIX2NX_LIVE_ATTACK=true: downloads and tests against the full ~30MB bundle.
"""

import os

import pytest

LIVE_FLAG = os.environ.get("STIX2NX_LIVE_ATTACK", "false").lower() == "true"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
SUBSET_PATH = os.path.join(os.path.dirname(__file__), "data", "attack-subset.json")

# Minimum thresholds: low enough for the subset, meaningful enough to catch breakage
MIN_NODES = 80
MIN_EDGES = 80


@pytest.fixture
def attack_bundle_path(tmp_path):
    """Get ATT&CK bundle. Default: curated subset. With STIX2NX_LIVE_ATTACK=true: full live bundle."""
    if LIVE_FLAG:
        try:
            import requests

            resp = requests.get(ATTACK_URL, timeout=120)
            resp.raise_for_status()
            live_path = tmp_path / "enterprise-attack.json"
            live_path.write_text(resp.text)
            print(
                f"\nUsing live ATT&CK bundle from {ATTACK_URL} "
                f"({len(resp.text) // 1024 // 1024}MB)"
            )
            return str(live_path)
        except Exception as e:
            print(
                f"\nLive ATT&CK download failed ({e}), falling back to curated subset"
            )
            return SUBSET_PATH
    return SUBSET_PATH


def test_attack_loads(attack_bundle_path):
    """ATT&CK bundle converts to a graph without error."""
    from stix2nx import stix_to_graph

    G = stix_to_graph(attack_bundle_path)
    assert len(G.nodes) >= MIN_NODES
    assert len(G.edges) >= MIN_EDGES


def test_attack_has_expected_types(attack_bundle_path):
    """ATT&CK graph contains the core node types."""
    from stix2nx import stix_to_graph

    G = stix_to_graph(attack_bundle_path)
    types = {data["type"] for _, data in G.nodes(data=True)}
    assert "attack-pattern" in types
    assert "intrusion-set" in types
    assert "malware" in types
    assert "tool" in types
    assert "relationship" not in types  # relationships should be edges, not nodes


def test_attack_relationship_attributes(attack_bundle_path):
    """Edges have relationship_type attributes."""
    from stix2nx import stix_to_graph

    G = stix_to_graph(attack_bundle_path)
    rel_types = set()
    for u, v, data in G.edges(data=True):
        if "relationship_type" in data:
            rel_types.add(data["relationship_type"])
    assert "uses" in rel_types  # ATT&CK heavily uses "uses" relationships


def test_attack_node_attributes(attack_bundle_path):
    """Nodes have expected STIX attributes preserved."""
    from stix2nx import stix_to_graph

    G = stix_to_graph(attack_bundle_path)
    # Find any attack-pattern node and verify it has a name
    for n, data in G.nodes(data=True):
        if data.get("type") == "attack-pattern":
            assert "name" in data
            assert "id" in data
            assert isinstance(data["id"], str)
            break


def test_attack_digraph(attack_bundle_path):
    """ATT&CK converts to DiGraph without error."""
    from stix2nx import stix_to_graph

    G = stix_to_graph(attack_bundle_path, graph_type="digraph")
    assert len(G.nodes) >= MIN_NODES


def test_attack_no_scos(attack_bundle_path):
    """ATT&CK converts with include_scos=False without error."""
    from stix2nx import stix_to_graph

    G_with = stix_to_graph(attack_bundle_path, include_scos=True)
    G_without = stix_to_graph(attack_bundle_path, include_scos=False)
    # With SCOs should have >= as many nodes
    assert len(G_with.nodes) >= len(G_without.nodes)


def test_attack_sightings(attack_bundle_path):
    """Sighting objects in the subset become nodes with edges."""
    from stix2nx import stix_to_graph

    G = stix_to_graph(attack_bundle_path)
    sighting_nodes = [
        n for n, d in G.nodes(data=True) if d.get("type") == "sighting"
    ]
    # The curated subset includes synthetic sightings
    assert len(sighting_nodes) >= 1
    # Each sighting should have at least a sighting_of edge
    for sn in sighting_nodes:
        edge_types = [d.get("relationship_type") for _, _, d in G.edges(sn, data=True)]
        assert "sighting_of" in edge_types
