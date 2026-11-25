"""Deterministic OCSF v1.1.0 mapper & STIX 2.1 indicator extractor."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

_DOMAIN_RE = re.compile(r"\[domain-name:value\s*=\s*'([a-zA-Z0-9.-]{3,253})'\]")
_IPV4_RE = re.compile(r"\[ipv4-addr:value\s*=\s*'(\d{1,3}(?:\.\d{1,3}){3})'\]")
_SHA256_RE = re.compile(r"\[file:hashes\.'SHA-256'\s*=\s*'([0-9a-fA-F]{64})'\]")


def to_ocsf_v110(
    *,
    organization_id: str,
    event_kind: str,
    agent_id: str | None = None,
    severity_id: int = 3,
    summary: str = "",
    chain_hash: str | None = None,
) -> dict[str, Any]:
    """Converts a RedHand event into an OCSF v1.1.0 Detection Finding (class_uid 2004)."""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": max(1, min(6, severity_id)),
        "time": now_ms,
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "RedHand",
                "vendor_name": "Archtificial",
                "feature": {"name": event_kind},
            },
        },
        "cloud": {"account": {"uid": organization_id}},
        "actor": {"app_name": agent_id or "system"},
        "finding_info": {
            "uid": chain_hash or event_kind,
            "title": event_kind,
            "desc": summary[:512] if summary else f"RedHand security signal: {event_kind}",
        },
        "unmapped": {
            "redhand_chain_hash": chain_hash,
        },
    }


def extract_stix_indicators(bundle: dict[str, Any]) -> list[tuple[str, str, str, int]]:
    """Extracts `(indicator_type, value, stix_id, confidence)` tuples from a STIX 2.1 Bundle."""
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        return []
    extracted: list[tuple[str, str, str, int]] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = str(obj.get("pattern") or "")
        stix_id = str(obj.get("id") or "indicator--unknown")[:128]
        raw_conf = obj.get("confidence", 80)
        confidence = int(raw_conf) if isinstance(raw_conf, int) else 80
        confidence = max(0, min(100, confidence))
        for m in _DOMAIN_RE.finditer(pattern):
            extracted.append(("domain", m.group(1).lower(), stix_id, confidence))
        for m in _IPV4_RE.finditer(pattern):
            extracted.append(("ipv4", m.group(1), stix_id, confidence))
        for m in _SHA256_RE.finditer(pattern):
            extracted.append(("sha256", m.group(1).lower(), stix_id, confidence))
    return extracted
