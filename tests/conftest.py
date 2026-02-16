"""Shared test fixtures with hand-crafted minimal STIX bundles."""

import json

import pytest


@pytest.fixture
def basic_bundle():
    """A minimal STIX 2.1 bundle with SDOs and relationships."""
    return {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Evil Corp",
                "aliases": ["BadGuys", "Villains"],
                "threat_actor_types": ["criminal"],
                "sophistication": "expert",
            },
            {
                "type": "malware",
                "id": "malware--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "EvilLoader",
                "is_family": True,
                "malware_types": ["trojan", "downloader"],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Spearphishing",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "attack-pattern--1",
            },
        ],
    }


@pytest.fixture
def basic_bundle_json(basic_bundle):
    """The basic bundle as a JSON string."""
    return json.dumps(basic_bundle)


@pytest.fixture
def empty_bundle():
    """An empty STIX bundle with no objects."""
    return {
        "type": "bundle",
        "id": "bundle--empty",
        "objects": [],
    }


@pytest.fixture
def nodes_only_bundle():
    """A bundle with SDO nodes but no relationships."""
    return {
        "type": "bundle",
        "id": "bundle--nodes-only",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--solo",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Lone Wolf",
            },
            {
                "type": "malware",
                "id": "malware--solo",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Orphan Malware",
                "is_family": False,
            },
        ],
    }


@pytest.fixture
def marking_bundle():
    """A bundle containing marking definitions and language content (should be skipped)."""
    return {
        "type": "bundle",
        "id": "bundle--marking",
        "objects": [
            {
                "type": "marking-definition",
                "id": "marking-definition--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "definition_type": "statement",
                "definition": {"statement": "Copyright 2023"},
            },
            {
                "type": "language-content",
                "id": "language-content--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "object_ref": "threat-actor--1",
                "object_modified": "2023-01-01T00:00:00.000Z",
                "contents": {"de": {"name": "Boese Firma"}},
            },
            {
                "type": "threat-actor",
                "id": "threat-actor--with-marking",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Marked Actor",
            },
        ],
    }


@pytest.fixture
def sco_bundle():
    """A bundle with various SCO types."""
    return {
        "type": "bundle",
        "id": "bundle--sco",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Malicious IP",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "pattern_type": "stix",
                "valid_from": "2023-01-01T00:00:00.000Z",
            },
            {
                "type": "ipv4-addr",
                "id": "ipv4-addr--1",
                "spec_version": "2.1",
                "value": "198.51.100.1",
            },
            {
                "type": "domain-name",
                "id": "domain-name--1",
                "spec_version": "2.1",
                "value": "evil.example.com",
            },
            {
                "type": "file",
                "id": "file--1",
                "spec_version": "2.1",
                "name": "malware.exe",
                "hashes": {
                    "SHA-256": "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
                    "MD5": "aabbccdd11223344aabbccdd11223344",
                },
                "size": 1024,
            },
            {
                "type": "url",
                "id": "url--1",
                "spec_version": "2.1",
                "value": "https://evil.example.com/payload",
            },
            {
                "type": "email-addr",
                "id": "email-addr--1",
                "spec_version": "2.1",
                "value": "attacker@evil.example.com",
            },
            {
                "type": "relationship",
                "id": "relationship--sco1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "based-on",
                "source_ref": "indicator--1",
                "target_ref": "ipv4-addr--1",
            },
        ],
    }


@pytest.fixture
def sighting_bundle():
    """A bundle with sighting objects and their referenced entities."""
    return {
        "type": "bundle",
        "id": "bundle--sighting",
        "objects": [
            {
                "type": "identity",
                "id": "identity--org1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "ACME Corp",
                "identity_class": "organization",
            },
            {
                "type": "indicator",
                "id": "indicator--sighted",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Bad Indicator",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "pattern_type": "stix",
                "valid_from": "2023-01-01T00:00:00.000Z",
            },
            {
                "type": "observed-data",
                "id": "observed-data--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "first_observed": "2023-01-01T00:00:00.000Z",
                "last_observed": "2023-01-01T00:00:00.000Z",
                "number_observed": 5,
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--sighted",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Threat Group Alpha",
            },
            {
                "type": "sighting",
                "id": "sighting--full",
                "spec_version": "2.1",
                "created": "2023-06-15T10:00:00.000Z",
                "modified": "2023-06-15T10:00:00.000Z",
                "first_seen": "2023-06-01T00:00:00.000Z",
                "last_seen": "2023-06-15T00:00:00.000Z",
                "count": 3,
                "sighting_of_ref": "indicator--sighted",
                "where_sighted_refs": ["identity--org1"],
                "observed_data_refs": ["observed-data--1"],
            },
            {
                "type": "sighting",
                "id": "sighting--minimal",
                "spec_version": "2.1",
                "created": "2023-07-01T00:00:00.000Z",
                "modified": "2023-07-01T00:00:00.000Z",
                "sighting_of_ref": "intrusion-set--sighted",
            },
        ],
    }


@pytest.fixture
def multi_edge_bundle():
    """A bundle where the same node pair has multiple relationships."""
    return {
        "type": "bundle",
        "id": "bundle--multi-edge",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--multi",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Multi Actor",
            },
            {
                "type": "malware",
                "id": "malware--multi",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Multi Malware",
                "is_family": True,
            },
            {
                "type": "relationship",
                "id": "relationship--multi1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--multi",
                "target_ref": "malware--multi",
            },
            {
                "type": "relationship",
                "id": "relationship--multi2",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "attributed-to",
                "source_ref": "threat-actor--multi",
                "target_ref": "malware--multi",
            },
        ],
    }


@pytest.fixture
def stix20_bundle():
    """A STIX 2.0 bundle with spec_version on the bundle and embedded SCOs."""
    return {
        "type": "bundle",
        "id": "bundle--stix20",
        "spec_version": "2.0",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--20",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "Legacy Actor",
                "labels": ["criminal"],
            },
            {
                "type": "malware",
                "id": "malware--20",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "Legacy Malware",
                "labels": ["trojan"],
            },
            {
                "type": "relationship",
                "id": "relationship--20",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--20",
                "target_ref": "malware--20",
            },
            {
                "type": "observed-data",
                "id": "observed-data--20",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "first_observed": "2020-01-01T00:00:00.000Z",
                "last_observed": "2020-01-01T00:00:00.000Z",
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "ipv4-addr",
                        "value": "203.0.113.50",
                    },
                    "1": {
                        "type": "domain-name",
                        "value": "legacy.example.com",
                    },
                },
            },
        ],
    }


@pytest.fixture
def stix21_bundle():
    """A STIX 2.1 bundle with 2.1-specific types."""
    return {
        "type": "bundle",
        "id": "bundle--stix21",
        "objects": [
            {
                "type": "infrastructure",
                "id": "infrastructure--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "C2 Server",
                "infrastructure_types": ["command-and-control"],
            },
            {
                "type": "location",
                "id": "location--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Eastern Europe",
                "region": "eastern-europe",
            },
            {
                "type": "malware-analysis",
                "id": "malware-analysis--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "product": "CuckooSandbox",
                "result": "malicious",
            },
            {
                "type": "note",
                "id": "note--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "content": "This actor is highly dangerous.",
                "object_refs": ["threat-actor--1"],
            },
            {
                "type": "opinion",
                "id": "opinion--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "opinion": "strongly-agree",
                "object_refs": ["threat-actor--1"],
            },
            {
                "type": "grouping",
                "id": "grouping--1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Threat Cluster Alpha",
                "context": "suspicious-activity",
                "object_refs": ["infrastructure--1", "location--1"],
            },
            {
                "type": "relationship",
                "id": "relationship--21-1",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "located-at",
                "source_ref": "infrastructure--1",
                "target_ref": "location--1",
            },
        ],
    }


@pytest.fixture
def merge_bundle_a():
    """First bundle for merge tests."""
    return {
        "type": "bundle",
        "id": "bundle--a",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--merge-a",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Actor A",
            },
            {
                "type": "malware",
                "id": "malware--shared",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Shared Malware v1",
                "is_family": True,
            },
            {
                "type": "relationship",
                "id": "relationship--merge-a",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--merge-a",
                "target_ref": "malware--shared",
            },
        ],
    }


@pytest.fixture
def merge_bundle_b():
    """Second bundle for merge tests (overlapping malware--shared node)."""
    return {
        "type": "bundle",
        "id": "bundle--b",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--merge-b",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Actor B",
            },
            {
                "type": "malware",
                "id": "malware--shared",
                "spec_version": "2.1",
                "created": "2023-02-01T00:00:00.000Z",
                "modified": "2023-02-01T00:00:00.000Z",
                "name": "Shared Malware v2",
                "is_family": False,
            },
            {
                "type": "relationship",
                "id": "relationship--merge-b",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--merge-b",
                "target_ref": "malware--shared",
            },
        ],
    }


@pytest.fixture
def merge_bundle_c():
    """Third bundle for merge tests (completely new nodes)."""
    return {
        "type": "bundle",
        "id": "bundle--c",
        "objects": [
            {
                "type": "tool",
                "id": "tool--merge-c",
                "spec_version": "2.1",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "Hack Tool",
                "tool_types": ["exploitation"],
            },
        ],
    }
