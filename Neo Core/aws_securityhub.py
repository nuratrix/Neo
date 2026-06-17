"""Alternate discovery source: AWS Security Hub.

If you aggregate Inspector (and other scanners) into Security Hub, pull from here
instead of Inspector directly -- the finding-provider account already sees every
member account's vulnerabilities in one place. Normalizes ASFF into the same
`Finding` model, so enrichment/scoring/reporting are unchanged.

`boto3` is imported lazily so the scoring/demo path needs no AWS credentials.
"""
from __future__ import annotations

from .models import Finding

# ASFF resource type -> our canonical type (so aws_context resolves exposure the same way)
_TYPE_MAP = {
    "AwsEc2Instance": "AWS_EC2_INSTANCE",
    "AwsEcrContainerImage": "AWS_ECR_CONTAINER_IMAGE",
    "AwsLambdaFunction": "AWS_LAMBDA_FUNCTION",
}


def _cvss_base(vuln: dict) -> float:
    scores = vuln.get("Cvss", []) or []
    if not scores:
        return 0.0
    return max(float(s.get("BaseScore", 0.0)) for s in scores)


def normalize_asff(finding: dict):
    """One ASFF finding may list several CVEs -> emit one Finding per CVE."""
    resources = finding.get("Resources", []) or [{}]
    res = resources[0]
    sev = (finding.get("Severity", {}) or {}).get("Label", "UNKNOWN")
    out = []
    for vuln in finding.get("Vulnerabilities", []) or []:
        pkgs = vuln.get("VulnerablePackages", []) or []
        out.append(
            Finding(
                finding_id=finding.get("Id", ""),
                cve_id=vuln.get("Id", ""),
                title=finding.get("Title", ""),
                severity=sev,
                cvss_base=_cvss_base(vuln),
                resource_id=res.get("Id", ""),
                resource_type=_TYPE_MAP.get(res.get("Type", ""), res.get("Type", "")),
                account_id=finding.get("AwsAccountId", ""),
                region=res.get("Region", ""),
                package_name=pkgs[0].get("Name", "") if pkgs else "",
                fix_available=vuln.get("FixAvailable", "") == "YES",
                exploit_available=vuln.get("ExploitAvailable", "") == "YES",
                first_observed=str(finding.get("FirstObservedAt", "")),
            )
        )
    return out


def pull_findings(region: str = "us-east-1", max_results: int = 5000, profile: str | None = None):
    """Return list[Finding] of active CVE findings aggregated in Security Hub."""
    import boto3  # lazy
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    client = session.client("securityhub", region_name=region)

    paginator = client.get_paginator("get_findings")
    filters = {
        "Type": [{"Value": "Software and Configuration Checks/Vulnerabilities/CVE", "Comparison": "PREFIX"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"},
                           {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
    }

    findings: list[Finding] = []
    for page in paginator.paginate(Filters=filters):
        for f in page.get("Findings", []):
            findings.extend(normalize_asff(f))
            if len(findings) >= max_results:
                return findings
    return findings
