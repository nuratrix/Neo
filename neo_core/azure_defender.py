"""Discovery: Microsoft Defender for Cloud vulnerability findings (sub-assessments).

Sub-assessments are the CVE-level findings Defender for Servers / Containers
produces for each VM, container image, or AKS node. They mirror AWS Inspector v2
and normalize into the same Finding model.

SETUP (real mode)
-----------------
1. Enable Defender for Servers Plan 2 (or Containers) on the subscription.
2. Create an App Registration and grant it Security Reader on the subscription:
       az ad sp create-for-rbac --name neo-reader \\
           --role "Security Reader" \\
           --scopes /subscriptions/{SUB_ID}
3. Set env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
   OR rely on DefaultAzureCredential (managed identity, CLI login, etc.)

DEPENDENCIES (real mode only)
------------------------------
    pip install azure-identity azure-mgmt-security
"""
from __future__ import annotations

import os

from .models import Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _mock_findings(subscription_id: str) -> list[Finding]:
    return [
        Finding(
            finding_id=f"azure-{subscription_id}-CVE-2024-3094",
            cve_id="CVE-2024-3094",
            title="xz/liblzma backdoor",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id=f"/subscriptions/{subscription_id}/resourceGroups/prod-rg"
                        f"/providers/Microsoft.Compute/virtualMachines/batch-vm-01",
            resource_type="Microsoft.Compute/virtualMachines",
            account_id=subscription_id,
            region="eastus",
            package_name="xz-utils",
            fix_available=True,
            exploit_available=True,
            cloud_provider="azure",
        ),
        Finding(
            finding_id=f"azure-{subscription_id}-CVE-2021-44228",
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 Remote Code Execution (Log4Shell)",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id=f"/subscriptions/{subscription_id}/resourceGroups/prod-rg"
                        f"/providers/Microsoft.Compute/virtualMachines/web-vm-01",
            resource_type="Microsoft.Compute/virtualMachines",
            account_id=subscription_id,
            region="eastus",
            package_name="log4j-core",
            fix_available=True,
            exploit_available=True,
            cloud_provider="azure",
        ),
    ]


def _cvss_from_additional(additional: dict) -> float:
    for cve_entry in (additional or {}).get("cve", []):
        cvss = cve_entry.get("cvss", {})
        for ver in ("3.1", "3.0", "2.0"):
            score = cvss.get(ver, {}).get("base")
            if score:
                return float(score)
    return 0.0


def _resource_type_from_id(resource_id: str) -> str:
    """Extract 'Namespace/Type' from an Azure resource ID."""
    parts = resource_id.split("/providers/")
    if len(parts) < 2:
        return "unknown"
    tail = parts[-1]
    segments = tail.split("/")
    if len(segments) >= 2:
        return f"{segments[0]}/{segments[1]}"
    return tail


def pull_findings(
    subscription_id: str,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    max_results: int = 1000,
) -> list[Finding]:
    """Return list[Finding] from Defender for Cloud sub-assessments for a subscription."""
    if MOCK_MODE:
        return _mock_findings(subscription_id)

    from azure.identity import ClientSecretCredential, DefaultAzureCredential  # type: ignore
    from azure.mgmt.security import SecurityCenter  # type: ignore

    cred = (
        ClientSecretCredential(tenant_id, client_id, client_secret)
        if tenant_id and client_id and client_secret
        else DefaultAzureCredential()
    )
    # asc_location is required by the client constructor but not used by sub_assessments
    client = SecurityCenter(cred, subscription_id, "centralus")
    scope = f"/subscriptions/{subscription_id}"

    findings: list[Finding] = []
    for sa in client.sub_assessments.list_all(scope=scope):
        props = getattr(sa, "additional_properties", {}) or {}
        additional = props.get("additionalData", {}) or {}

        cve_entries = additional.get("cve", [])
        if not cve_entries:
            continue  # skip config/posture findings — we want CVE-level vulns only

        resource_id = (props.get("resourceDetails") or {}).get("id", sa.id or "")
        sev_raw = (props.get("status") or {}).get("severity", "UNKNOWN")
        severity = _SEVERITY_MAP.get(sev_raw.lower(), sev_raw.upper())
        cvss = _cvss_from_additional(additional)

        for cve_entry in cve_entries:
            cve_id = cve_entry.get("title", "")
            if not cve_id:
                continue
            findings.append(
                Finding(
                    finding_id=f"{sa.name or ''}-{cve_id}",
                    cve_id=cve_id,
                    title=props.get("displayName", ""),
                    severity=severity,
                    cvss_base=cvss,
                    resource_id=resource_id,
                    resource_type=_resource_type_from_id(resource_id),
                    account_id=subscription_id,
                    region="",  # resolved by azure_context
                    package_name=additional.get("packageName", ""),
                    fix_available=bool(additional.get("patchable", False)),
                    exploit_available=False,
                    cloud_provider="azure",
                )
            )
            if len(findings) >= max_results:
                return findings

    return findings
