"""Environmental context for on-premises resources.

On-prem scanners (Nessus, Qualys, Rapid7) return findings keyed by IP address
or hostname. Unlike cloud APIs, there is no single authoritative API to query
for exposure or criticality — so this module supports two sources:

  1. Context map file (default, zero dependencies)
     A JSON file mapping IP/hostname to exposure/criticality/controls.
     Maintained by the asset owner; committed to the repo or an S3/blob bucket.

  2. ServiceNow CMDB (optional)
     Queries the Table API for Configuration Items matching the finding's
     IP address, reading business criticality and environment fields.

If neither source has an entry for a given resource, the context defaults to
exposure="unknown", criticality="unknown" — the risk engine handles unknowns
gracefully rather than crashing.

CONTEXT MAP FILE FORMAT
-----------------------
{
  "10.0.1.100": {
    "exposure": "public",
    "criticality": "critical",
    "compensating_controls": 0.0,
    "note": "public-facing web server"
  },
  "db-prod-01.corp": {
    "exposure": "internal",
    "criticality": "high",
    "compensating_controls": 0.3
  }
}

DEPENDENCIES
------------
  Context map file: none (standard library only)
  ServiceNow:       pip install httpx  (already a project dependency)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

from .models import AssetContext, Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}


# ---------------------------------------------------------------------------
# Context map file source
# ---------------------------------------------------------------------------

def _load_context_map(path: str) -> dict[str, dict]:
    """Load and return the context map JSON, or empty dict on failure."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _context_from_map(resource_id: str, context_map: dict) -> AssetContext | None:
    entry = context_map.get(resource_id)
    if not entry:
        return None
    return AssetContext(
        resource_id=resource_id,
        exposure=entry.get("exposure", "unknown"),
        criticality=entry.get("criticality", "unknown"),
        compensating_controls=float(entry.get("compensating_controls", 0.0)),
    )


# ---------------------------------------------------------------------------
# ServiceNow CMDB source (optional)
# ---------------------------------------------------------------------------

def _snow_query(
    instance_url: str,
    username: str,
    password: str,
    ip_address: str,
    timeout: float = 15.0,
) -> AssetContext | None:
    """Query ServiceNow CMDB for a CI by IP address.

    Reads:
      u_criticality / u_business_criticality  → criticality
      u_environment                           → exposure (prod=public, dev=internal, etc.)
    Adjust field names to match your CMDB schema.
    """
    url = f"{instance_url.rstrip('/')}/api/now/table/cmdb_ci_server"
    try:
        resp = httpx.get(
            url,
            params={"sysparm_query": f"ip_address={ip_address}", "sysparm_limit": "1",
                    "sysparm_fields": "name,ip_address,u_criticality,u_environment"},
            auth=(username, password),
            timeout=timeout,
        )
        resp.raise_for_status()
        records = resp.json().get("result", [])
        if not records:
            return None
        rec = records[0]
        raw_env = rec.get("u_environment", "").lower()
        exposure = "public" if raw_env in ("prod", "production", "internet-facing") else "internal"
        crit = rec.get("u_criticality", "unknown").lower()
        return AssetContext(resource_id=ip_address, exposure=exposure, criticality=crit)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_contexts(
    findings: list[Finding],
    context_map_path: str | None = None,
    snow_instance_url: str | None = None,
    snow_username: str | None = None,
    snow_password: str | None = None,
) -> dict[str, AssetContext]:
    """Return {resource_id: AssetContext} for the resources in findings.

    Resolution order per resource:
      1. Context map file (if path provided)
      2. ServiceNow CMDB (if ServiceNow credentials provided)
      3. Default: exposure=unknown, criticality=unknown
    """
    if MOCK_MODE:
        contexts: dict[str, AssetContext] = {}
        for f in findings:
            if f.resource_id in contexts:
                continue
            exposure = "public" if f.resource_id.endswith(".10") else "internal"
            contexts[f.resource_id] = AssetContext(
                resource_id=f.resource_id,
                exposure=exposure,
                criticality="high" if exposure == "public" else "medium",
            )
        return contexts

    context_map = _load_context_map(context_map_path) if context_map_path else {}
    snow_enabled = bool(snow_instance_url and snow_username and snow_password)

    contexts: dict[str, AssetContext] = {}
    for f in findings:
        rid = f.resource_id
        if rid in contexts:
            continue

        ctx = _context_from_map(rid, context_map)

        if ctx is None and snow_enabled:
            ctx = _snow_query(snow_instance_url, snow_username, snow_password, rid)  # type: ignore[arg-type]

        if ctx is None:
            ctx = AssetContext(resource_id=rid)  # all defaults: unknown / 0.0

        contexts[rid] = ctx

    return contexts
