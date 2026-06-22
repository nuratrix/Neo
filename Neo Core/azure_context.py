"""Environmental context for Azure resources.

Resolves exposure and business criticality for Azure VMs (and containers)
by inspecting network configuration and resource tags — the Azure equivalent
of aws_context.py.

Exposure logic:
  VM has no public IP                       → internal
  VM has public IP, NSG blocks 0.0.0.0/0   → internal
  VM has public IP, NSG allows 0.0.0.0/0   → public
  Cannot determine (permissions/error)     → unknown

Criticality and compensating controls come from Azure resource tags,
using the same tag-key convention as the AWS layer so the scoring engine
sees a uniform AssetContext regardless of cloud.

DEPENDENCIES (real mode only)
------------------------------
    pip install azure-identity azure-mgmt-compute azure-mgmt-network
"""
from __future__ import annotations

import os

from .models import AssetContext, Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

CRITICALITY_TAG_KEYS = ("Criticality", "criticality", "BusinessCriticality")
CONTROLS_TAG_KEY = "CompensatingControls"


# ---------------------------------------------------------------------------
# Tag helpers (identical contract to aws_context.py)
# ---------------------------------------------------------------------------

def _criticality_from_tags(tags: dict) -> str:
    for k in CRITICALITY_TAG_KEYS:
        if k in tags:
            return tags[k].strip().lower()
    return "unknown"


def _controls_from_tags(tags: dict) -> float:
    try:
        return float(tags.get(CONTROLS_TAG_KEY, 0.0))
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Azure resource ID parsing
# ---------------------------------------------------------------------------

def _parse_resource_id(resource_id: str) -> tuple[str, str, str, str]:
    """Return (subscription_id, resource_group, namespace_type, resource_name)."""
    parts = resource_id.lower().split("/")
    try:
        sub  = parts[parts.index("subscriptions") + 1]
        rg   = parts[parts.index("resourcegroups") + 1]
        prov = parts[parts.index("providers") + 1]
        # providers/{ns}/{type}/{name}
        rtype = parts[parts.index(prov) + 1]
        rname = parts[parts.index(rtype) + 1]
        return sub, rg, f"{prov}/{rtype}", rname
    except (ValueError, IndexError):
        return "", "", "", ""


# ---------------------------------------------------------------------------
# Exposure resolution
# ---------------------------------------------------------------------------

def _vm_exposure(compute, network, resource_group: str, vm_name: str) -> tuple[str, dict]:
    """Return (exposure, tags) for an Azure VM."""
    try:
        vm = compute.virtual_machines.get(resource_group, vm_name, expand="instanceView")
    except Exception:
        return "unknown", {}

    tags = {k: v for k, v in (vm.tags or {}).items()}

    # Find the primary NIC
    nics = vm.network_profile.network_interfaces if vm.network_profile else []
    if not nics:
        return "internal", tags

    nic_id = nics[0].id  # e.g. /subscriptions/.../networkInterfaces/my-nic
    nic_rg  = _parse_resource_id(nic_id)[1]
    nic_name = nic_id.split("/")[-1]

    try:
        nic = network.network_interfaces.get(nic_rg, nic_name)
    except Exception:
        return "unknown", tags

    # Check for public IP on the NIC's primary IP config
    has_public_ip = False
    for ip_cfg in (nic.ip_configurations or []):
        if ip_cfg.public_ip_address:
            has_public_ip = True
            break

    if not has_public_ip:
        return "internal", tags

    # Has a public IP — check NSG for any inbound 0.0.0.0/0 rule
    nsg = nic.network_security_group
    if nsg is None:
        return "public", tags  # no NSG = fully open

    try:
        nsg_rg   = _parse_resource_id(nsg.id)[1]
        nsg_name = nsg.id.split("/")[-1]
        nsg_obj  = network.network_security_groups.get(nsg_rg, nsg_name)
        for rule in (nsg_obj.security_rules or []):
            if (rule.direction == "Inbound"
                    and rule.access == "Allow"
                    and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")):
                return "public", tags
        return "internal", tags  # public IP but NSG restricts inbound
    except Exception:
        return "public", tags  # assume exposed if NSG check fails


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_contexts(
    findings: list[Finding],
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> dict[str, AssetContext]:
    """Return {resource_id: AssetContext} for the resources in findings."""
    if MOCK_MODE:
        contexts: dict[str, AssetContext] = {}
        for f in findings:
            if f.resource_id in contexts:
                continue
            # Mock: web-vm-01 is public+critical, everything else is internal
            exposure = "public" if "web" in f.resource_id else "internal"
            contexts[f.resource_id] = AssetContext(
                resource_id=f.resource_id,
                exposure=exposure,
                criticality="critical" if "web" in f.resource_id else "medium",
                compensating_controls=0.0,
            )
        return contexts

    from azure.identity import ClientSecretCredential, DefaultAzureCredential  # type: ignore
    from azure.mgmt.compute import ComputeManagementClient  # type: ignore
    from azure.mgmt.network import NetworkManagementClient  # type: ignore

    cred = (
        ClientSecretCredential(tenant_id, client_id, client_secret)
        if tenant_id and client_id and client_secret
        else DefaultAzureCredential()
    )

    contexts = {}
    compute_clients: dict[str, ComputeManagementClient] = {}
    network_clients: dict[str, NetworkManagementClient] = {}

    for f in findings:
        if f.resource_id in contexts or f.cloud_provider != "azure":
            continue

        sub, rg, rtype, rname = _parse_resource_id(f.resource_id)
        if not sub:
            contexts[f.resource_id] = AssetContext(resource_id=f.resource_id)
            continue

        if sub not in compute_clients:
            compute_clients[sub] = ComputeManagementClient(cred, sub)
            network_clients[sub] = NetworkManagementClient(cred, sub)

        if "virtualmachines" in rtype.lower():
            exposure, tags = _vm_exposure(compute_clients[sub], network_clients[sub], rg, rname)
        else:
            exposure, tags = "internal", {}

        contexts[f.resource_id] = AssetContext(
            resource_id=f.resource_id,
            exposure=exposure,
            criticality=_criticality_from_tags(tags),
            compensating_controls=_controls_from_tags(tags),
            tags=tags,
        )

    return contexts
