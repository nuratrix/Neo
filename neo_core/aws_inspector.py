"""Discovery layer: pull vulnerability findings from AWS Inspector v2.

Inspector v2 continuously scans EC2 instances, ECR container images, and Lambda
functions and emits per-CVE findings. This module normalizes them into the
source-agnostic `Finding` model. To go multi-account, point this at a delegated
admin account or aggregate via Security Hub instead.

`boto3` is imported lazily so the scoring/demo path needs no AWS credentials.
"""
from __future__ import annotations

from .models import Finding, ecosystem_from_package_manager


def _cvss_base(pvd: dict) -> float:
    scores = pvd.get("cvss", []) or []
    if not scores:
        return 0.0
    # Prefer the highest base score reported (sources can disagree).
    return max(float(s.get("baseScore", 0.0)) for s in scores)


def pull_findings(region: str = "us-east-1", max_results: int = 1000, profile: str | None = None):
    """Return list[Finding] of active package-vulnerability findings."""
    import boto3  # lazy
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    client = session.client("inspector2", region_name=region)

    paginator = client.get_paginator("list_findings")
    filter_criteria = {
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
    }

    findings: list[Finding] = []
    for page in paginator.paginate(filterCriteria=filter_criteria):
        for f in page.get("findings", []):
            findings.append(normalize_finding(f, region))
            if len(findings) >= max_results:
                return findings
    return findings


def normalize_finding(f: dict, default_region: str = "us-east-1") -> Finding:
    pvd = f.get("packageVulnerabilityDetails", {}) or {}
    resources = f.get("resources", []) or [{}]
    res = resources[0]
    pkgs = pvd.get("vulnerablePackages", []) or []
    pkg = pkgs[0] if pkgs else {}
    return Finding(
        finding_id=f.get("findingArn", ""),
        cve_id=pvd.get("vulnerabilityId", ""),
        title=f.get("title", ""),
        severity=f.get("severity", "UNKNOWN"),
        cvss_base=_cvss_base(pvd),
        resource_id=res.get("id", ""),
        resource_type=res.get("type", ""),
        account_id=f.get("awsAccountId", ""),
        region=res.get("region", default_region),
        package_name=pkg.get("name", ""),
        package_ecosystem=ecosystem_from_package_manager(pkg.get("packageManager", "")),
        fixed_version=pkg.get("fixedInVersion", "") or "",
        fix_available=f.get("fixAvailable", "") == "YES",
        exploit_available=f.get("exploitAvailable", "") == "YES",
        first_observed=str(f.get("firstObservedAt", "")),
    )
