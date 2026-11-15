"""Discovery: Rapid7 InsightVM (API v3).

Enumerates all assets then fetches per-asset vulnerabilities. Batches
vulnerability-detail lookups to resolve CVE IDs without an individual API
call per finding.

SETUP (real mode)
-----------------
1. InsightVM console URL: https://your-console:3780
2. Create an API user (Administration → Users) with the "Report Viewer" role.
3. Set env vars:
       RAPID7_URL=https://your-console:3780
       RAPID7_USERNAME=neo-reader
       RAPID7_PASSWORD=your-password

DEPENDENCIES (real mode only)
------------------------------
    pip install httpx   (already a project dependency)
"""
from __future__ import annotations

import os

import httpx

from .models import Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

_R7_SEV = {
    "Critical": "CRITICAL",
    "Severe": "HIGH",
    "Moderate": "MEDIUM",
    "Low": "LOW",
}


def _mock_findings(scanner_url: str) -> list[Finding]:
    host = scanner_url or "rapid7-host"
    return [
        Finding(
            finding_id=f"r7-{host}-CVE-2024-3094-10.0.3.50",
            cve_id="CVE-2024-3094",
            title="xz/liblzma backdoor",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id="10.0.3.50",
            resource_type="host",
            account_id=host,
            region="onprem",
            package_name="xz-utils",
            fix_available=True,
            exploit_available=True,
            cloud_provider="onprem",
        ),
        Finding(
            finding_id=f"r7-{host}-CVE-2021-44228-10.0.3.10",
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 Remote Code Execution (Log4Shell)",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id="10.0.3.10",
            resource_type="host",
            account_id=host,
            region="onprem",
            package_name="log4j-core",
            fix_available=True,
            exploit_available=True,
            cloud_provider="onprem",
        ),
    ]


def _paginate(client: httpx.Client, path: str, resource_key: str, page_size: int = 500) -> list[dict]:
    """Generic InsightVM v3 paginator."""
    results: list[dict] = []
    page = 0
    while True:
        resp = client.get(path, params={"page": page, "size": page_size}).raise_for_status().json()
        batch = resp.get(resource_key, [])
        results.extend(batch)
        if resp.get("page", {}).get("totalPages", 1) <= page + 1:
            break
        page += 1
    return results


def _vuln_details_batch(
    client: httpx.Client, vuln_ids: list[str]
) -> dict[str, dict]:
    """Fetch vulnerability metadata for a list of vuln IDs.
    Returns {vuln_id: {cves, title, severity, cvss_v3_score, exploits}}.
    """
    details: dict[str, dict] = {}
    for vid in vuln_ids:
        try:
            v = client.get(f"/api/3/vulnerabilities/{vid}").raise_for_status().json()
            cvss_score = (
                (v.get("cvss") or {}).get("v3", {}).get("score")
                or (v.get("cvss") or {}).get("v2", {}).get("score")
                or 0.0
            )
            details[vid] = {
                "cves": v.get("cves", []),
                "title": v.get("title", vid),
                "severity": v.get("severity", ""),
                "cvss": float(cvss_score),
                "exploits": int(v.get("exploits", 0)),
            }
        except Exception:
            details[vid] = {"cves": [], "title": vid, "severity": "", "cvss": 0.0, "exploits": 0}
    return details


def pull_findings(
    scanner_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    max_results: int = 5000,
    verify_ssl: bool = False,
) -> list[Finding]:
    """Return list[Finding] from Rapid7 InsightVM."""
    url  = scanner_url or os.getenv("RAPID7_URL", "")
    user = username    or os.getenv("RAPID7_USERNAME", "")
    pwd  = password    or os.getenv("RAPID7_PASSWORD", "")

    if MOCK_MODE:
        return _mock_findings(url)

    findings: list[Finding] = []
    seen: set[str] = set()

    with httpx.Client(base_url=url, auth=(user, pwd),
                      verify=verify_ssl, timeout=60.0) as client:
        assets = _paginate(client, "/api/3/assets", "resources")

        # Collect all unique vuln IDs across assets before hitting the detail endpoint
        asset_vulns: list[tuple[dict, list[dict]]] = []
        unique_vuln_ids: set[str] = set()

        for asset in assets:
            asset_id = asset.get("id")
            if not asset_id:
                continue
            vulns = _paginate(client, f"/api/3/assets/{asset_id}/vulnerabilities", "resources")
            asset_vulns.append((asset, vulns))
            unique_vuln_ids.update(v.get("id", "") for v in vulns if v.get("id"))

        vuln_meta = _vuln_details_batch(client, list(unique_vuln_ids))

    for asset, vulns in asset_vulns:
        ip = (asset.get("addresses") or [{}])[0].get("ip", "")
        hostname = asset.get("hostName", ip) or ip
        resource_id = hostname or ip or str(asset.get("id", "unknown"))

        for v in vulns:
            vid = v.get("id", "")
            meta = vuln_meta.get(vid, {})
            cves: list[str] = meta.get("cves", [])
            if not cves:
                continue

            exploits = meta.get("exploits", 0)
            severity = _R7_SEV.get(meta.get("severity", ""), "UNKNOWN")

            for cve_id in cves:
                key = f"{resource_id}-{cve_id}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        finding_id=f"r7-{vid}-{resource_id}-{cve_id}",
                        cve_id=cve_id,
                        title=meta.get("title", ""),
                        severity=severity,
                        cvss_base=meta.get("cvss", 0.0),
                        resource_id=resource_id,
                        resource_type="host",
                        account_id=url,
                        region="onprem",
                        package_name="",
                        fix_available=True,
                        exploit_available=exploits > 0,
                        cloud_provider="onprem",
                    )
                )
                if len(findings) >= max_results:
                    return findings

    return findings
