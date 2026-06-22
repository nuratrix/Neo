"""Discovery: Nessus Professional / Essentials vulnerability scanner.

Pulls findings from a Nessus instance via its REST API. Uses the CSV export
path to get CVE data in one download rather than one plugin-API call per
vulnerability (which would be O(unique_plugins) round-trips).

SETUP (real mode)
-----------------
1. In Nessus UI: Settings → My Account → API Keys → Generate.
2. Set env vars:
       NESSUS_URL=https://your-nessus-host:8834
       NESSUS_ACCESS_KEY=<access_key>
       NESSUS_SECRET_KEY=<secret_key>
   Or pass them directly to pull_findings().

DEPENDENCIES (real mode only)
------------------------------
    pip install httpx   (already a project dependency)
"""
from __future__ import annotations

import csv
import io
import os
import time

import httpx

from .models import Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

_NESSUS_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "none": "INFORMATIONAL"}
_POLL_INTERVAL = 3   # seconds between export-status polls
_POLL_TIMEOUT  = 120 # seconds before giving up on export


def _mock_findings(scanner_url: str) -> list[Finding]:
    host = scanner_url or "nessus-host"
    return [
        Finding(
            finding_id=f"nessus-{host}-CVE-2024-3094-10.0.1.50",
            cve_id="CVE-2024-3094",
            title="xz/liblzma backdoor",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id="10.0.1.50",
            resource_type="host",
            account_id=host,
            region="onprem",
            package_name="xz-utils",
            fix_available=True,
            exploit_available=True,
            cloud_provider="onprem",
        ),
        Finding(
            finding_id=f"nessus-{host}-CVE-2021-44228-10.0.1.10",
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 Remote Code Execution (Log4Shell)",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id="10.0.1.10",
            resource_type="host",
            account_id=host,
            region="onprem",
            package_name="log4j-core",
            fix_available=True,
            exploit_available=True,
            cloud_provider="onprem",
        ),
    ]


def _auth_headers(access_key: str, secret_key: str) -> dict[str, str]:
    return {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}


def _latest_completed_scan(client: httpx.Client) -> int | None:
    resp = client.get("/scans").raise_for_status().json()
    completed = [s for s in (resp.get("scans") or []) if s.get("status") == "completed"]
    if not completed:
        return None
    return sorted(completed, key=lambda s: s.get("last_modification_date", 0), reverse=True)[0]["id"]


def _export_csv(client: httpx.Client, scan_id: int) -> str:
    """Export a scan as CSV and return the raw CSV text."""
    file_id = client.post(
        f"/scans/{scan_id}/export", json={"format": "csv"}
    ).raise_for_status().json()["file"]

    deadline = time.time() + _POLL_TIMEOUT
    while time.time() < deadline:
        status = client.get(f"/scans/{scan_id}/export/{file_id}/status").raise_for_status().json()
        if status.get("status") == "ready":
            break
        time.sleep(_POLL_INTERVAL)

    return client.get(f"/scans/{scan_id}/export/{file_id}/download").raise_for_status().text


def _parse_csv(csv_text: str, scanner_url: str) -> list[Finding]:
    """Parse Nessus CSV export into Finding objects.

    Nessus CSV columns (relevant ones):
    Plugin ID, CVE, CVSS v2.0 Base Score, Risk, Host, Protocol, Port,
    Name, Synopsis, Description, Solution, Plugin Output
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        risk = row.get("Risk", "").lower()
        if risk in ("none", ""):
            continue  # informational — skip
        raw_cves = row.get("CVE", "").strip()
        if not raw_cves:
            continue

        host = row.get("Host", "unknown")
        for cve_id in [c.strip() for c in raw_cves.split(",") if c.strip()]:
            key = f"{host}-{cve_id}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    finding_id=f"nessus-{host}-{cve_id}-{row.get('Port', '0')}",
                    cve_id=cve_id,
                    title=row.get("Name", ""),
                    severity=_NESSUS_SEV.get(risk, "UNKNOWN"),
                    cvss_base=float(row.get("CVSS v2.0 Base Score") or row.get("CVSS v3.0 Base Score") or 0.0),
                    resource_id=host,
                    resource_type="host",
                    account_id=scanner_url,
                    region="onprem",
                    package_name="",
                    fix_available=bool(row.get("Solution", "").strip()),
                    exploit_available=False,
                    cloud_provider="onprem",
                )
            )
    return findings


def pull_findings(
    scanner_url: str | None = None,
    access_key: str | None = None,
    secret_key: str | None = None,
    scan_id: int | None = None,
    max_results: int = 5000,
    verify_ssl: bool = False,
) -> list[Finding]:
    """Return list[Finding] from a Nessus scan (most recent completed if scan_id omitted)."""
    url = scanner_url or os.getenv("NESSUS_URL", "")
    ak  = access_key  or os.getenv("NESSUS_ACCESS_KEY", "")
    sk  = secret_key  or os.getenv("NESSUS_SECRET_KEY", "")

    if MOCK_MODE:
        return _mock_findings(url)

    with httpx.Client(base_url=url, headers=_auth_headers(ak, sk),
                      verify=verify_ssl, timeout=60.0) as client:
        sid = scan_id or _latest_completed_scan(client)
        if sid is None:
            return []
        csv_text = _export_csv(client, sid)

    findings = _parse_csv(csv_text, url)
    return findings[:max_results]
