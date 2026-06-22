"""Environmental context for GCP resources.

Resolves exposure and business criticality for GCP Compute instances by
inspecting network configuration and instance labels — the GCP equivalent
of aws_context.py.

Exposure logic:
  Instance has no external IP                             → internal
  Instance has external IP, firewall blocks 0.0.0.0/0    → internal
  Instance has external IP, firewall allows 0.0.0.0/0    → public
  Cannot determine (permissions/error)                   → unknown

Criticality and compensating controls come from GCP instance labels
using the same key convention (lowercase) as the AWS/Azure layers.

DEPENDENCIES (real mode only)
------------------------------
    pip install google-cloud-compute
"""
from __future__ import annotations

import os

from .models import AssetContext, Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

CRITICALITY_LABEL_KEYS = ("criticality", "business_criticality")
CONTROLS_LABEL_KEY = "compensating_controls"


# ---------------------------------------------------------------------------
# Label helpers
# ---------------------------------------------------------------------------

def _criticality_from_labels(labels: dict) -> str:
    for k in CRITICALITY_LABEL_KEYS:
        if k in labels:
            return labels[k].strip().lower()
    return "unknown"


def _controls_from_labels(labels: dict) -> float:
    try:
        raw = labels.get(CONTROLS_LABEL_KEY, "0")
        # GCP labels are strings; interpret values like "0_3" as 0.3
        return float(raw.replace("_", "."))
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# GCP resource name parsing
# //compute.googleapis.com/projects/{proj}/zones/{zone}/instances/{name}
# ---------------------------------------------------------------------------

def _parse_resource_name(resource_name: str) -> tuple[str, str, str]:
    """Return (project_id, zone, instance_name) or empty strings on failure."""
    try:
        path = resource_name.split("googleapis.com/")[-1]  # projects/.../zones/.../instances/...
        parts = path.split("/")
        proj  = parts[parts.index("projects") + 1]
        zone  = parts[parts.index("zones") + 1]
        name  = parts[parts.index("instances") + 1]
        return proj, zone, name
    except (ValueError, IndexError):
        return "", "", ""


# ---------------------------------------------------------------------------
# Exposure resolution
# ---------------------------------------------------------------------------

def _has_external_ip(instance) -> bool:
    for iface in (instance.network_interfaces or []):
        for access_config in (iface.access_configs or []):
            if access_config.nat_i_p:   # NAT IP = external IP
                return True
    return False


def _firewall_allows_world(compute_client, project_id: str, instance) -> bool:
    """Return True if any VPC firewall rule allows ingress from 0.0.0.0/0."""
    # Collect network names and tags from instance
    networks = {
        iface.network.rsplit("/", 1)[-1]
        for iface in (instance.network_interfaces or [])
        if iface.network
    }
    tags = list((instance.tags or {}).get("items", []) if hasattr(instance.tags, "get") else [])

    try:
        rules_pager = compute_client.firewalls().list(project=project_id).execute()
        for rule in rules_pager.get("items", []):
            if rule.get("direction", "INGRESS") != "INGRESS":
                continue
            sources = rule.get("sourceRanges", [])
            if "0.0.0.0/0" not in sources:
                continue
            # Rule targets all instances or matches this instance's network/tags
            target_tags = rule.get("targetTags", [])
            target_sa = rule.get("targetServiceAccounts", [])
            if not target_tags and not target_sa:
                return True  # applies to all instances in the network
            if any(t in tags for t in target_tags):
                return True
    except Exception:
        return True  # assume exposed if check fails (safe default for a public IP host)

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_contexts(
    findings: list[Finding],
    credentials_path: str | None = None,
) -> dict[str, AssetContext]:
    """Return {resource_id: AssetContext} for the resources in findings."""
    if MOCK_MODE:
        contexts: dict[str, AssetContext] = {}
        for f in findings:
            if f.resource_id in contexts:
                continue
            exposure = "public" if "web" in f.resource_id else "internal"
            contexts[f.resource_id] = AssetContext(
                resource_id=f.resource_id,
                exposure=exposure,
                criticality="critical" if "web" in f.resource_id else "medium",
                compensating_controls=0.0,
            )
        return contexts

    import os as _os
    if credentials_path:
        _os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

    from googleapiclient import discovery  # type: ignore  # pip install google-api-python-client
    import google.auth  # type: ignore

    creds, _ = google.auth.default()
    compute_client = discovery.build("compute", "v1", credentials=creds)

    contexts: dict[str, AssetContext] = {}

    for f in findings:
        if f.resource_id in contexts or f.cloud_provider != "gcp":
            continue

        proj, zone, inst_name = _parse_resource_name(f.resource_id)
        if not proj or not inst_name:
            contexts[f.resource_id] = AssetContext(resource_id=f.resource_id)
            continue

        try:
            instance = compute_client.instances().get(
                project=proj, zone=zone, instance=inst_name
            ).execute()
        except Exception:
            contexts[f.resource_id] = AssetContext(resource_id=f.resource_id)
            continue

        labels = instance.get("labels", {})
        has_ext_ip = _has_external_ip(type("obj", (), {"network_interfaces": [
            type("iface", (), {
                "access_configs": [type("ac", (), {"nat_i_p": ac.get("natIP")})()
                                   for ac in iface.get("accessConfigs", [])],
                "network": iface.get("network"),
            })()
            for iface in instance.get("networkInterfaces", [])
        ]})())

        if not has_ext_ip:
            exposure = "internal"
        elif _firewall_allows_world(compute_client, proj, instance):
            exposure = "public"
        else:
            exposure = "internal"

        contexts[f.resource_id] = AssetContext(
            resource_id=f.resource_id,
            exposure=exposure,
            criticality=_criticality_from_labels(labels),
            compensating_controls=_controls_from_labels(labels),
            tags=labels,
        )

    return contexts
