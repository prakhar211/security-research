"""
STIX 2.1 Writer — outputs extracted IOCs as a STIX Bundle.

Generates valid STIX 2.1 JSON without requiring the stix2 library
(zero external dependencies for this module).
"""

import json
import os
import uuid
from datetime import datetime

# IOC type → STIX SCO type mapping
STIX_TYPE_MAP = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "url": "url",
    "email": "email-addr",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


def _stix_id(type_name: str) -> str:
    """Generate a deterministic-format STIX ID."""
    return f"{type_name}--{uuid.uuid4()}"


def _ioc_to_stix_object(ioc) -> dict:
    """Convert a single IOC to a STIX Cyber Observable (SCO)."""
    stix_type = STIX_TYPE_MAP.get(ioc.type)
    if not stix_type:
        return None

    obj = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": _stix_id(stix_type),
    }

    if stix_type == "ipv4-addr":
        obj["value"] = ioc.value
    elif stix_type == "ipv6-addr":
        obj["value"] = ioc.value
    elif stix_type == "domain-name":
        obj["value"] = ioc.value
    elif stix_type == "url":
        obj["value"] = ioc.value
    elif stix_type == "email-addr":
        obj["value"] = ioc.value
    elif stix_type == "file":
        # File objects use hashes
        hash_type_map = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
        obj["hashes"] = {hash_type_map[ioc.type]: ioc.value}

    return obj


def _create_indicator(ioc, sco_id: str, campaign_name: str) -> dict:
    """Create a STIX Indicator (SDO) referencing the SCO."""
    pattern_map = {
        "ipv4": f"[ipv4-addr:value = '{ioc.value}']",
        "ipv6": f"[ipv6-addr:value = '{ioc.value}']",
        "domain": f"[domain-name:value = '{ioc.value}']",
        "url": f"[url:value = '{ioc.value}']",
        "email": f"[email-addr:value = '{ioc.value}']",
        "md5": f"[file:hashes.MD5 = '{ioc.value}']",
        "sha1": f"[file:hashes.'SHA-1' = '{ioc.value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{ioc.value}']",
    }

    pattern = pattern_map.get(ioc.type)
    if not pattern:
        return None

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator"),
        "created": now,
        "modified": now,
        "name": f"{ioc.type.upper()}: {ioc.defanged}",
        "description": f"Extracted from threat intel scrape — campaign: {campaign_name}. "
                        f"Source: {ioc.source}",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["threat-intel-scraper", campaign_name],
    }


def write_stix_bundle(
    iocs: list,
    output_path: str,
    campaign_name: str = "scrape",
    include_indicators: bool = True,
) -> str:
    """
    Write IOCs as a STIX 2.1 Bundle.

    Args:
        iocs: List of IOC objects.
        output_path: Directory to write the file.
        campaign_name: Campaign/scrape identifier.
        include_indicators: Whether to include Indicator SDOs alongside SCOs.

    Returns:
        Path to the written STIX JSON file.
    """
    os.makedirs(output_path, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    filename = f"{campaign_name}-{timestamp}.stix2.json"
    filepath = os.path.join(output_path, filename)

    objects = []

    for ioc in iocs:
        sco = _ioc_to_stix_object(ioc)
        if sco:
            objects.append(sco)

            if include_indicators:
                indicator = _create_indicator(ioc, sco["id"], campaign_name)
                if indicator:
                    objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    return filepath
