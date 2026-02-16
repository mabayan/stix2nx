#!/usr/bin/env python3
"""Build a curated ~1MB subset of the MITRE ATT&CK Enterprise STIX bundle.

Downloads the full ATT&CK Enterprise bundle and extracts a representative subset
containing ~200-300 objects with referential integrity. The subset includes core
ATT&CK types plus synthetic SCOs and sightings for comprehensive testing.

Usage:
    python tests/data/build_subset.py
"""

import json
import os
import sys
from collections import Counter

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "attack-subset.json")

# Target intrusion sets by name (well-connected, well-known groups)
TARGET_INTRUSION_SETS = {
    "APT28",
    "APT29",
    "Lazarus Group",
    "FIN7",
    "Turla",
    "Kimsuky",
    "Wizard Spider",
    "Sandworm Team",
}

# Target tools by name
TARGET_TOOLS = {
    "Mimikatz",
    "Cobalt Strike",
    "PsExec",
    "Impacket",
    "BloodHound",
}


def download_bundle():
    """Download the full ATT&CK Enterprise STIX bundle."""
    import requests

    print(f"Downloading ATT&CK bundle from {ATTACK_URL}...")
    resp = requests.get(ATTACK_URL, timeout=120)
    resp.raise_for_status()
    bundle = resp.json()
    print(f"Downloaded {len(resp.text) // 1024 // 1024}MB, {len(bundle.get('objects', []))} objects")
    return bundle


def build_subset(bundle):
    """Extract a curated subset from the full ATT&CK bundle."""
    objects = bundle.get("objects", [])

    # Index objects by ID and type
    by_id = {}
    by_type = {}
    for obj in objects:
        obj_id = obj.get("id")
        obj_type = obj.get("type")
        if obj_id:
            by_id[obj_id] = obj
        if obj_type:
            by_type.setdefault(obj_type, []).append(obj)

    selected_ids = set()
    selected_objects = []

    def select(obj):
        obj_id = obj.get("id")
        if obj_id and obj_id not in selected_ids:
            selected_ids.add(obj_id)
            selected_objects.append(obj)

    # 1. x-mitre-matrix and x-mitre-tactic objects (ATT&CK matrix structure)
    for obj in by_type.get("x-mitre-matrix", []):
        select(obj)
    for obj in by_type.get("x-mitre-tactic", []):
        select(obj)

    # 2. Identity objects (MITRE identity used as created_by_ref)
    for obj in by_type.get("identity", []):
        select(obj)

    # 3. Target intrusion sets
    intrusion_sets = by_type.get("intrusion-set", [])
    for obj in intrusion_sets:
        if obj.get("name") in TARGET_INTRUSION_SETS:
            select(obj)

    # 4. Target tools
    tools = by_type.get("tool", [])
    for obj in tools:
        if obj.get("name") in TARGET_TOOLS:
            select(obj)

    # 5. Collect all relationships
    relationships = by_type.get("relationship", [])

    # Find malware and attack-patterns connected to selected intrusion sets
    connected_malware = set()
    connected_attack_patterns = set()
    for rel in relationships:
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if src in selected_ids:
            if tgt.startswith("malware--"):
                connected_malware.add(tgt)
            elif tgt.startswith("attack-pattern--"):
                connected_attack_patterns.add(tgt)
        if tgt in selected_ids:
            if src.startswith("malware--"):
                connected_malware.add(src)
            elif src.startswith("attack-pattern--"):
                connected_attack_patterns.add(src)

    # 6. Select malware (up to ~10, prioritize most connected)
    malware_connection_count = Counter(connected_malware)
    top_malware = [mid for mid, _ in malware_connection_count.most_common(10)]
    for mid in top_malware:
        if mid in by_id:
            select(by_id[mid])

    # 7. Select attack-patterns (up to ~30, prioritize most connected)
    ap_connection_count = Counter()
    for rel in relationships:
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if tgt.startswith("attack-pattern--") and tgt in connected_attack_patterns:
            ap_connection_count[tgt] += 1
        if src.startswith("attack-pattern--") and src in connected_attack_patterns:
            ap_connection_count[src] += 1
    top_aps = [apid for apid, _ in ap_connection_count.most_common(30)]
    for apid in top_aps:
        if apid in by_id:
            select(by_id[apid])

    # 8. Select campaigns (up to ~5)
    campaigns = by_type.get("campaign", [])
    campaign_count = 0
    for rel in relationships:
        if campaign_count >= 5:
            break
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if src.startswith("campaign--") and (tgt in selected_ids):
            if src in by_id and src not in selected_ids:
                select(by_id[src])
                campaign_count += 1
        elif tgt.startswith("campaign--") and (src in selected_ids):
            if tgt in by_id and tgt not in selected_ids:
                select(by_id[tgt])
                campaign_count += 1

    # 9. Select courses of action (up to ~3)
    coas = by_type.get("course-of-action", [])
    coa_count = 0
    for rel in relationships:
        if coa_count >= 3:
            break
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if src.startswith("course-of-action--") and tgt in selected_ids:
            if src in by_id and src not in selected_ids:
                select(by_id[src])
                coa_count += 1
        elif tgt.startswith("course-of-action--") and src in selected_ids:
            if tgt in by_id and tgt not in selected_ids:
                select(by_id[tgt])
                coa_count += 1

    # 10. Select vulnerability objects (up to ~5)
    vulns = by_type.get("vulnerability", [])
    for obj in vulns[:5]:
        select(obj)

    # 11. Select all relationships where BOTH endpoints are in our selected set
    for rel in relationships:
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if src in selected_ids and tgt in selected_ids:
            select(rel)

    # 12. Add synthetic SCOs (ATT&CK is SDO-focused, so we add these for test coverage)
    synthetic_scos = [
        {
            "type": "ipv4-addr",
            "id": "ipv4-addr--synthetic-001",
            "spec_version": "2.1",
            "value": "198.51.100.42",
        },
        {
            "type": "domain-name",
            "id": "domain-name--synthetic-001",
            "spec_version": "2.1",
            "value": "c2.adversary.example.com",
        },
        {
            "type": "file",
            "id": "file--synthetic-001",
            "spec_version": "2.1",
            "name": "payload.dll",
            "hashes": {
                "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "MD5": "d41d8cd98f00b204e9800998ecf8427e",
            },
            "size": 45056,
        },
        {
            "type": "url",
            "id": "url--synthetic-001",
            "spec_version": "2.1",
            "value": "https://c2.adversary.example.com/beacon",
        },
    ]
    # Synthetic indicators referencing the SCOs
    synthetic_indicators = [
        {
            "type": "indicator",
            "id": "indicator--synthetic-001",
            "spec_version": "2.1",
            "created": "2024-01-15T00:00:00.000Z",
            "modified": "2024-01-15T00:00:00.000Z",
            "name": "Malicious IP Indicator",
            "pattern": "[ipv4-addr:value = '198.51.100.42']",
            "pattern_type": "stix",
            "valid_from": "2024-01-15T00:00:00.000Z",
            "indicator_types": ["malicious-activity"],
        },
        {
            "type": "indicator",
            "id": "indicator--synthetic-002",
            "spec_version": "2.1",
            "created": "2024-01-15T00:00:00.000Z",
            "modified": "2024-01-15T00:00:00.000Z",
            "name": "Malicious File Indicator",
            "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
            "pattern_type": "stix",
            "valid_from": "2024-01-15T00:00:00.000Z",
            "indicator_types": ["malicious-activity"],
        },
    ]
    # Synthetic relationships connecting indicators to SCOs
    synthetic_rels = [
        {
            "type": "relationship",
            "id": "relationship--synthetic-001",
            "spec_version": "2.1",
            "created": "2024-01-15T00:00:00.000Z",
            "modified": "2024-01-15T00:00:00.000Z",
            "relationship_type": "based-on",
            "source_ref": "indicator--synthetic-001",
            "target_ref": "ipv4-addr--synthetic-001",
        },
        {
            "type": "relationship",
            "id": "relationship--synthetic-002",
            "spec_version": "2.1",
            "created": "2024-01-15T00:00:00.000Z",
            "modified": "2024-01-15T00:00:00.000Z",
            "relationship_type": "based-on",
            "source_ref": "indicator--synthetic-002",
            "target_ref": "file--synthetic-001",
        },
    ]

    # Pick a real intrusion set ID for sighting references
    real_intrusion_set_id = None
    real_identity_id = None
    for obj in selected_objects:
        if obj.get("type") == "intrusion-set" and real_intrusion_set_id is None:
            real_intrusion_set_id = obj["id"]
        if obj.get("type") == "identity" and real_identity_id is None:
            real_identity_id = obj["id"]

    # 13. Add synthetic sightings
    synthetic_sightings = [
        {
            "type": "sighting",
            "id": "sighting--synthetic-001",
            "spec_version": "2.1",
            "created": "2024-02-01T12:00:00.000Z",
            "modified": "2024-02-01T12:00:00.000Z",
            "first_seen": "2024-01-20T00:00:00.000Z",
            "last_seen": "2024-01-31T00:00:00.000Z",
            "count": 5,
            "sighting_of_ref": "indicator--synthetic-001",
            "where_sighted_refs": [real_identity_id] if real_identity_id else [],
        },
        {
            "type": "sighting",
            "id": "sighting--synthetic-002",
            "spec_version": "2.1",
            "created": "2024-02-15T08:00:00.000Z",
            "modified": "2024-02-15T08:00:00.000Z",
            "first_seen": "2024-02-10T00:00:00.000Z",
            "last_seen": "2024-02-14T00:00:00.000Z",
            "count": 2,
            "sighting_of_ref": real_intrusion_set_id or "indicator--synthetic-001",
        },
    ]

    # Add all synthetic objects
    for obj in (
        synthetic_scos
        + synthetic_indicators
        + synthetic_rels
        + synthetic_sightings
    ):
        select(obj)

    # Build the output bundle
    subset_bundle = {
        "type": "bundle",
        "id": "bundle--attack-subset",
        "objects": selected_objects,
    }

    # Verify referential integrity
    final_ids = {obj["id"] for obj in selected_objects if "id" in obj}
    dangling = 0
    for obj in selected_objects:
        if obj.get("type") == "relationship":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src not in final_ids:
                dangling += 1
            if tgt not in final_ids:
                dangling += 1

    return subset_bundle, dangling


def print_summary(subset_bundle, dangling):
    """Print a summary of the subset."""
    objects = subset_bundle["objects"]
    type_counts = Counter(obj.get("type") for obj in objects)

    print(f"\n{'='*50}")
    print("ATT&CK Subset Summary")
    print(f"{'='*50}")
    print(f"Total objects: {len(objects)}")
    print(f"File size: {len(json.dumps(subset_bundle)) // 1024}KB")
    print(f"Dangling references: {dangling}")
    print(f"\nObject counts by type:")
    for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {type_name}: {count}")

    # Count nodes vs edges
    node_types = {
        t for t in type_counts if t not in ("relationship",)
    }
    node_count = sum(type_counts[t] for t in node_types)
    edge_count = type_counts.get("relationship", 0)
    print(f"\nGraph summary:")
    print(f"  Nodes: {node_count}")
    print(f"  Edges (relationships): {edge_count}")
    print(f"  Sightings: {type_counts.get('sighting', 0)}")


def main():
    bundle = download_bundle()
    subset_bundle, dangling = build_subset(bundle)

    # Write output
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(subset_bundle, f, indent=2)
    print(f"\nWrote subset to {OUTPUT_PATH}")

    print_summary(subset_bundle, dangling)


if __name__ == "__main__":
    main()
