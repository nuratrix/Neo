"""Discovery: Google Cloud Security Command Center (SCC) vulnerability findings.

SCC aggregates findings from Container Analysis, OS vulnerability scanning,
Web Security Scanner, and third-party sources. This module pulls findings whose
category indicates a CVE-level package vulnerability and normalizes them into
the shared Finding model.

SETUP (real mode)
-----------------
1. Enable Security Command Center (Standard or Premium) on the project/org.
2. Create a Service Account with "Security Center Findings Viewer" role.
3. Either:
   a. Export a JSON key and set GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
   b. Use Workload Identity (if running on GCP)
   c. Run `gcloud auth application-default login` locally

DEPENDENCIES (real mode only)
------------------------------
    pip install google-cloud-securitycenter
"""
from __future__ import annotations

import os

from .models import Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

_GCP_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _mock_findings(project_id: str) -> list[Finding]:
    return [
        Finding(
            finding_id=f"projects/{project_id}/sources/123/findings/cve-2024-3094",
            cve_id="CVE-2024-3094",
            title="xz/liblzma backdoor",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id=f"//compute.googleapis.com/projects/{project_id}/zones/us-central1-a/instances/batch-instance-01",
            resource_type="google.compute.Instance",
            account_id=project_id,
            region="us-central1",
            package_name="xz-utils",
            fix_available=True,
            exploit_available=True,
            cloud_provider="gcp",
        ),
        Finding(
            finding_id=f"projects/{project_id}/sources/123/findings/cve-2021-44228",
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 Remote Code Execution (Log4Shell)",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id=f"//compute.googleapis.com/projects/{project_id}/zones/us-central1-a/instances/web-instance-01",
            resource_type="google.compute.Instance",
            account_id=project_id,
            region="us-central1",
            package_name="log4j-core",
            fix_available=True,
            exploit_available=True,
            cloud_provider="gcp",
        ),
    ]


def _parse_region(resource_name: str) -> str:
    """Extract region or zone from a GCP resource name."""
    for segment in ("zones/", "regions/"):
        if segment in resource_name:
            after = resource_name.split(segment, 1)[1]
            zone_or_region = after.split("/")[0]
            # Convert zone (us-central1-a) to region (us-central1)
            return "-".join(zone_or_region.split("-")[:-1]) if segment == "zones/" else zone_or_region
    return ""


def _cvss_from_vulnerability(vuln_dict: dict) -> float:
    cvss = vuln_dict.get("cvssv3") or vuln_dict.get("cvssv2") or {}
    return float(cvss.get("baseScore", 0.0))


def pull_findings(
    project_id: str,
    credentials_path: str | None = None,
    max_results: int = 1000,
) -> list[Finding]:
    """Return list[Finding] from SCC for a GCP project.

    Filters to active findings with a CVE category (OS vulnerabilities,
    container image vulnerabilities).
    """
    if MOCK_MODE:
        return _mock_findings(project_id)

    import os as _os
    if credentials_path:
        _os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

    from google.cloud import securitycenter  # type: ignore

    client = securitycenter.SecurityCenterClient()
    parent = f"projects/{project_id}/sources/-"

    # SCC finding filter: active findings that represent a CVE vulnerability
    finding_filter = (
        'state="ACTIVE" AND '
        '(category:"CVE" OR category:"OS_VULNERABILITY" OR '
        ' category:"PACKAGE_VULNERABILITY" OR category:"CONTAINER_VULNERABILITY")'
    )

    findings: list[Finding] = []
    request = securitycenter.ListFindingsRequest(
        parent=parent,
        filter=finding_filter,
        page_size=min(max_results, 1000),
    )

    for result in client.list_findings(request=request):
        f = result.finding
        src_props = dict(f.source_properties)

        # Extract CVE ID — SCC puts it in different places depending on the source
        cve_id = (
            src_props.get("CVE")
            or src_props.get("cve_id")
            or (f.category if f.category.startswith("CVE-") else "")
        )
        if not cve_id:
            continue

        vuln = getattr(f, "vulnerability", None)
        vuln_dict = {}
        if vuln:
            vuln_dict = {
                "cvssv3": {"baseScore": getattr(getattr(vuln, "cvssv3", None), "base_score", 0.0)},
            }

        findings.append(
            Finding(
                finding_id=f.name,
                cve_id=cve_id,
                title=src_props.get("description", f.category),
                severity=_GCP_SEV_MAP.get(f.severity.name, "UNKNOWN"),
                cvss_base=_cvss_from_vulnerability(vuln_dict),
                resource_id=f.resource_name,
                resource_type=src_props.get("resourceType", "google.compute.Instance"),
                account_id=project_id,
                region=_parse_region(f.resource_name),
                package_name=src_props.get("packageName", ""),
                fix_available=bool(src_props.get("fixAvailable", False)),
                exploit_available=False,
                cloud_provider="gcp",
            )
        )
        if len(findings) >= max_results:
            break

    return findings
