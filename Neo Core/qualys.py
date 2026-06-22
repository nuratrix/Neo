"""Discovery: Qualys VMDR (Vulnerability Management, Detection & Response).

Calls the Qualys Host List Detection API to retrieve active CVE findings
across managed hosts, then normalizes them into the shared Finding model.

SETUP (real mode)
-----------------
1. Qualys user must have API access and the VM module enabled.
2. Find your API URL at: Help → About (e.g. https://qualysapi.qualys.com
   or https://qualysapi.qg2.apps.qualys.eu — region-specific).
3. Set env vars:
       QUALYS_URL=https://qualysapi.qualys.com
       QUALYS_USERNAME=your-api-user
       QUALYS_PASSWORD=your-api-password

DEPENDENCIES (real mode only)
------------------------------
    pip install httpx   (already a project dependency)
    Standard library xml.etree.ElementTree handles the XML response.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET

import httpx

from .models import Finding

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}

# Qualys severity: 5=Critical, 4=High, 3=Medium, 2=Low, 1=Minimal
_QUALYS_SEV = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "LOW"}


def _mock_findings(scanner_url: str) -> list[Finding]:
    host = scanner_url or "qualys-host"
    return [
        Finding(
            finding_id=f"qualys-{host}-CVE-2024-3094-10.0.2.50",
            cve_id="CVE-2024-3094",
            title="xz/liblzma backdoor",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id="10.0.2.50",
            resource_type="host",
            account_id=host,
            region="onprem",
            package_name="xz-utils",
            fix_available=True,
            exploit_available=True,
            cloud_provider="onprem",
        ),
        Finding(
            finding_id=f"qualys-{host}-CVE-2021-44228-10.0.2.10",
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 Remote Code Execution (Log4Shell)",
            severity="CRITICAL",
            cvss_base=10.0,
            resource_id="10.0.2.10",
            resource_type="host",
            account_id=host,
            region="onprem",
            package_name="log4j-core",
            fix_available=True,
            exploit_available=True,
            cloud_provider="onprem",
        ),
    ]


def _text(el: ET.Element | None, tag: str, default: str = "") -> str:
    child = el.find(tag) if el is not None else None
    return child.text.strip() if child is not None and child.text else default


def _parse_xml(xml_text: str, scanner_url: str) -> list[Finding]:
    root = ET.fromstring(xml_text)
    findings: list[Finding] = []
    seen: set[str] = set()

    for host_el in root.findall(".//HOST"):
        ip = _text(host_el, "IP", "unknown")
        dns = _text(host_el, "DNS", ip)
        resource_id = dns or ip

        for det in host_el.findall(".//DETECTION"):
            status = _text(det, "STATUS")
            if status.lower() != "active":
                continue

            raw_cves = _text(det, "CVE_IDS")
            if not raw_cves:
                continue

            sev_int = int(_text(det, "SEVERITY", "0") or 0)
            severity = _QUALYS_SEV.get(sev_int, "UNKNOWN")
            cvss_base = float(_text(det, "CVSS_BASE", "0.0") or 0.0)
            title = _text(det, "TITLE") or _text(det, "RESULTS", "")[:120]
            qid = _text(det, "QID")

            for cve_id in [c.strip() for c in raw_cves.split(",") if c.strip()]:
                key = f"{resource_id}-{cve_id}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        finding_id=f"qualys-{qid}-{resource_id}-{cve_id}",
                        cve_id=cve_id,
                        title=title,
                        severity=severity,
                        cvss_base=cvss_base,
                        resource_id=resource_id,
                        resource_type="host",
                        account_id=scanner_url,
                        region="onprem",
                        package_name="",
                        fix_available=True,
                        exploit_available=False,
                        cloud_provider="onprem",
                    )
                )
    return findings


def pull_findings(
    scanner_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    severity_min: int = 3,
    max_results: int = 5000,
) -> list[Finding]:
    """Return list[Finding] from Qualys VMDR.

    severity_min filters to findings at or above the given level (3=Medium+).
    """
    url  = scanner_url or os.getenv("QUALYS_URL", "")
    user = username    or os.getenv("QUALYS_USERNAME", "")
    pwd  = password    or os.getenv("QUALYS_PASSWORD", "")

    if MOCK_MODE:
        return _mock_findings(url)

    severity_levels = ",".join(str(i) for i in range(severity_min, 6))

    with httpx.Client(base_url=url, auth=(user, pwd), timeout=60.0) as client:
        resp = client.post(
            "/api/2.0/fo/asset/host/vm/detection/",
            headers={"X-Requested-With": "project-neo"},
            data={
                "action": "list",
                "show_results": "1",
                "status": "Active",
                "severity_levels": severity_levels,
                "truncation_limit": str(max_results),
            },
        ).raise_for_status()

    findings = _parse_xml(resp.text, url)
    return findings[:max_results]
