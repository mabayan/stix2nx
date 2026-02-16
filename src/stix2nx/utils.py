"""Helper functions for STIX object type detection and processing."""

import logging

logger = logging.getLogger(__name__)

# STIX Domain Object types (SDOs)
SDO_TYPES = frozenset({
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "identity",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data",
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
})

# STIX Cyber-observable Object types (SCOs)
SCO_TYPES = frozenset({
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
})

# Types to skip entirely
SKIP_TYPES = frozenset({
    "marking-definition",
    "language-content",
})

# ATT&CK custom types treated as SDOs
CUSTOM_SDO_PREFIXES = ("x-mitre-",)


def is_sdo(obj: dict) -> bool:
    """Check if a STIX object is a Domain Object (SDO)."""
    obj_type = obj.get("type", "")
    if obj_type in SDO_TYPES:
        return True
    for prefix in CUSTOM_SDO_PREFIXES:
        if obj_type.startswith(prefix):
            return True
    return False


def is_sco(obj: dict) -> bool:
    """Check if a STIX object is a Cyber-observable Object (SCO)."""
    return obj.get("type", "") in SCO_TYPES


def is_relationship(obj: dict) -> bool:
    """Check if a STIX object is a Relationship."""
    return obj.get("type") == "relationship"


def is_sighting(obj: dict) -> bool:
    """Check if a STIX object is a Sighting."""
    return obj.get("type") == "sighting"


def is_skippable(obj: dict) -> bool:
    """Check if a STIX object should be skipped (marking-definition, language-content)."""
    return obj.get("type", "") in SKIP_TYPES


def extract_stix20_embedded_scos(observed_data: dict) -> list[dict]:
    """Extract embedded SCOs from a STIX 2.0 observed-data object.

    STIX 2.0 observed-data objects contain a nested `objects` dict with
    numeric string keys mapping to embedded observable objects. This function
    extracts them as standalone objects with synthetic IDs.

    Args:
        observed_data: A STIX 2.0 observed-data object dict.

    Returns:
        List of SCO dicts with synthetic IDs based on the parent observed-data ID.
    """
    embedded = observed_data.get("objects", {})
    if not isinstance(embedded, dict):
        return []

    parent_id = observed_data.get("id", "observed-data--unknown")
    scos = []

    for key, obj in embedded.items():
        if not isinstance(obj, dict):
            continue
        obj_type = obj.get("type", "")
        if not obj_type:
            continue
        sco = dict(obj)
        # Create a synthetic ID: parent-id--embedded-key
        sco["id"] = f"{parent_id}--embedded-{key}"
        if "type" not in sco:
            continue
        scos.append(sco)

    return scos
