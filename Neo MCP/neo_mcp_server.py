"""
Project Neo — MCP Server (Week 1: tools + resources)
====================================================

Exposes Neo's vulnerability-management capabilities over the Model Context
Protocol using the official MCP Python SDK (the bundled FastMCP).

WHAT THIS FILE PROVIDES
-----------------------
Tools (actions / side effects — "POST-like"):
  • run_vulnerability_scan      -> Nessus / Qualys / Rapid7 (one tool, pluggable adapters)
  • pull_aws_inspector_findings -> AWS Inspector v2
  • pull_aws_security_hub_findings -> AWS Security Hub
  • create_github_remediation_pr   -> opens a remediation PR on a GitHub repo

Resources (read-only context — "GET-like"):
  • kev://catalog            -> full CISA Known Exploited Vulnerabilities catalog
  • kev://entry/{cve_id}      -> a single KEV entry
  • epss://score/{cve_id}     -> EPSS exploitation-probability score for a CVE
  • scan://results/{scan_id}  -> full findings from a prior run_vulnerability_scan call

SETUP
-----
1. Create an environment and install dependencies:

       uv venv && source .venv/bin/activate      # or: python -m venv .venv && source .venv/bin/activate
       uv pip install "mcp[cli]" httpx boto3      # or: pip install "mcp[cli]" httpx boto3

2. Run it standalone in mock mode (no credentials needed — returns synthetic data):

       NEO_MOCK_MODE=true python neo_mcp_server.py

3. Inspect it interactively with the MCP Inspector:

       uv run mcp dev neo_mcp_server.py

4. Wire it into Claude Code (.mcp.json in the Neo repo root) or Claude Desktop
   (claude_desktop_config.json). Example entry:

       {
         "mcpServers": {
           "neo": {
             "command": "python",
             "args": ["/absolute/path/to/neo_mcp_server.py"],
             "env": { "NEO_MOCK_MODE": "true" }
           }
         }
       }

ENVIRONMENT VARIABLES
---------------------
  NEO_MOCK_MODE        "true" (default) returns synthetic data so the server runs
                       with zero credentials. Set "false" for live integrations.
  NEO_MCP_TRANSPORT    "stdio" (default), "streamable-http", or "sse".
  NEO_HTTP_TIMEOUT     HTTP timeout in seconds (default 30).
  GITHUB_TOKEN         PAT with repo scope (required when not in mock mode).
  NESSUS_URL / NESSUS_ACCESS_KEY / NESSUS_SECRET_KEY
  QUALYS_URL / QUALYS_USERNAME / QUALYS_PASSWORD
  RAPID7_URL / RAPID7_API_KEY
  AWS credentials are read from the standard boto3 chain (env, profile, role).
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Callable

import httpx
from pydantic import Field

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}
HTTP_TIMEOUT: float = float(os.getenv("NEO_HTTP_TIMEOUT", "30"))

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
GITHUB_API = "https://api.github.com"
KEV_CACHE_TTL = 6 * 60 * 60  # refresh the KEV catalog at most every 6 hours

mcp = FastMCP("neo")


# ---------------------------------------------------------------------------
# Typed enums  ->  these become tight JSON-schema constraints the model must
# respect, instead of free-form strings. This is the core of "well-scoped".
# ---------------------------------------------------------------------------

class Scanner(str, Enum):
    nessus = "nessus"
    qualys = "qualys"
    rapid7 = "rapid7"


class ScanProfile(str, Enum):
    discovery = "discovery"      # host/port discovery only
    basic = "basic"              # default authenticated scan
    full = "full"                # deep scan, all plugins
    compliance = "compliance"    # benchmark / policy audit


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


# In-memory store linking a scan run (tool) to its full results (resource).
# Swap for DynamoDB / S3 in production — the resource handler is the only reader.
_SCAN_STORE: dict[str, dict[str, Any]] = {}

# Simple time-based cache for the KEV catalog (it is ~1 MB of JSON).
_kev_cache: dict[str, Any] = {"data": None, "fetched_at": 0.0}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_breakdown(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# ---------------------------------------------------------------------------
# Scanner adapters
# One adapter per vendor. The MCP tool stays single and stable; vendors plug
# in here. This is where the real vendor HTTP calls go — the function shape is
# identical across vendors so the tool never changes when you add one.
# ---------------------------------------------------------------------------

def _mock_findings(source: str, target: str) -> list[dict[str, Any]]:
    """Synthetic findings so the server is runnable with zero credentials."""
    return [
        {
            "cve": "CVE-2024-3094",
            "title": "xz/liblzma backdoor",
            "severity": Severity.critical.value,
            "cvss": 10.0,
            "asset": target,
            "source": source,
            "package": "xz-utils",
            "fixed_version": "5.6.2",
        },
        {
            "cve": "CVE-2021-44228",
            "title": "Log4Shell remote code execution",
            "severity": Severity.high.value,
            "cvss": 9.8,
            "asset": target,
            "source": source,
            "package": "log4j-core",
            "fixed_version": "2.17.1",
        },
    ]


def _nessus_scan(target: str, profile: ScanProfile) -> list[dict[str, Any]]:
    if MOCK_MODE:
        return _mock_findings("nessus", target)
    # TODO(real): authenticate to Nessus (X-ApiKeys: accessKey=...; secretKey=...),
    # POST /scans to launch with the chosen policy, poll /scans/{id} until complete,
    # then GET /scans/{id} and normalize each vuln into the finding dict above.
    raise NotImplementedError("Set NEO_MOCK_MODE=false only after wiring the Nessus API.")


def _qualys_scan(target: str, profile: ScanProfile) -> list[dict[str, Any]]:
    if MOCK_MODE:
        return _mock_findings("qualys", target)
    # TODO(real): call the Qualys VM/VMDR API (launch scan, fetch results XML/JSON),
    # then normalize into the finding dict shape.
    raise NotImplementedError("Set NEO_MOCK_MODE=false only after wiring the Qualys API.")


def _rapid7_scan(target: str, profile: ScanProfile) -> list[dict[str, Any]]:
    if MOCK_MODE:
        return _mock_findings("rapid7", target)
    # TODO(real): call the Rapid7 InsightVM API (create/run a scan, fetch findings),
    # then normalize into the finding dict shape.
    raise NotImplementedError("Set NEO_MOCK_MODE=false only after wiring the Rapid7 API.")


SCANNER_ADAPTERS: dict[Scanner, Callable[[str, ScanProfile], list[dict[str, Any]]]] = {
    Scanner.nessus: _nessus_scan,
    Scanner.qualys: _qualys_scan,
    Scanner.rapid7: _rapid7_scan,
}


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
def run_vulnerability_scan(
    scanner: Annotated[Scanner, Field(description="Which on-prem scanner to use.")],
    target: Annotated[
        str,
        Field(description="Hostname, IP address, or CIDR range to scan.", min_length=1, max_length=255),
    ],
    profile: Annotated[
        ScanProfile, Field(description="Scan depth/policy to apply.")
    ] = ScanProfile.basic,
) -> dict[str, Any]:
    """Launch an on-prem vulnerability scan with the chosen scanner.

    Returns a compact summary and a scan_id. Fetch the full finding set via the
    `scan://results/{scan_id}` resource rather than dumping it into the response —
    keep large payloads out of the model's context until they are needed.
    """
    adapter = SCANNER_ADAPTERS[scanner]
    findings = adapter(target, profile)
    scan_id = f"{scanner.value}-{int(time.time())}"

    _SCAN_STORE[scan_id] = {
        "scan_id": scan_id,
        "scanner": scanner.value,
        "target": target,
        "profile": profile.value,
        "started_at": _now_iso(),
        "finding_count": len(findings),
        "findings": findings,
    }

    return {
        "scan_id": scan_id,
        "scanner": scanner.value,
        "target": target,
        "finding_count": len(findings),
        "severity_breakdown": _severity_breakdown(findings),
        "results_resource": f"scan://results/{scan_id}",
    }


@mcp.tool()
def pull_aws_inspector_findings(
    account_id: Annotated[str, Field(description="12-digit AWS account ID.", pattern=r"^\d{12}$")],
    region: Annotated[str, Field(description="AWS region, e.g. us-east-1.", min_length=1)],
    severities: Annotated[
        list[Severity], Field(description="Severity levels to include.")
    ] = [Severity.critical, Severity.high],
    max_results: Annotated[int, Field(description="Maximum findings to return.", ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Pull active findings from AWS Inspector v2 for an account and region."""
    if MOCK_MODE:
        findings = _mock_findings("aws-inspector", f"{account_id}/{region}")
        return {"source": "aws-inspector", "account_id": account_id, "region": region,
                "finding_count": len(findings), "findings": findings}

    import boto3  # imported lazily so mock mode needs no AWS deps

    client = boto3.client("inspector2", region_name=region)
    sev_filter = [{"comparison": "EQUALS", "value": s.value.upper()} for s in severities]
    resp = client.list_findings(
        filterCriteria={"awsAccountId": [{"comparison": "EQUALS", "value": account_id}],
                        "severity": sev_filter},
        maxResults=max_results,
    )
    findings = [
        {
            "cve": (f.get("packageVulnerabilityDetails") or {}).get("vulnerabilityId"),
            "title": f.get("title"),
            "severity": str(f.get("severity", "")).lower(),
            "cvss": ((f.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}).get("score"),
            "asset": (f.get("resources") or [{}])[0].get("id"),
            "source": "aws-inspector",
        }
        for f in resp.get("findings", [])
    ]
    return {"source": "aws-inspector", "account_id": account_id, "region": region,
            "finding_count": len(findings), "findings": findings}


@mcp.tool()
def pull_aws_security_hub_findings(
    account_id: Annotated[str, Field(description="12-digit AWS account ID.", pattern=r"^\d{12}$")],
    region: Annotated[str, Field(description="AWS region, e.g. us-east-1.", min_length=1)],
    severities: Annotated[
        list[Severity], Field(description="Severity labels to include.")
    ] = [Severity.critical, Severity.high],
    max_results: Annotated[int, Field(description="Maximum findings to return.", ge=1, le=100)] = 100,
) -> dict[str, Any]:
    """Pull active findings from AWS Security Hub for an account and region."""
    if MOCK_MODE:
        findings = _mock_findings("aws-security-hub", f"{account_id}/{region}")
        return {"source": "aws-security-hub", "account_id": account_id, "region": region,
                "finding_count": len(findings), "findings": findings}

    import boto3

    client = boto3.client("securityhub", region_name=region)
    sev_filter = [{"Value": s.value.upper(), "Comparison": "EQUALS"} for s in severities]
    resp = client.get_findings(
        Filters={"AwsAccountId": [{"Value": account_id, "Comparison": "EQUALS"}],
                 "SeverityLabel": sev_filter,
                 "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
        MaxResults=max_results,
    )
    findings = [
        {
            "cve": next(iter(f.get("Vulnerabilities", [{}])), {}).get("Id"),
            "title": f.get("Title"),
            "severity": str((f.get("Severity") or {}).get("Label", "")).lower(),
            "asset": (f.get("Resources") or [{}])[0].get("Id"),
            "source": "aws-security-hub",
        }
        for f in resp.get("Findings", [])
    ]
    return {"source": "aws-security-hub", "account_id": account_id, "region": region,
            "finding_count": len(findings), "findings": findings}


@mcp.tool()
def create_github_remediation_pr(
    repo: Annotated[
        str, Field(description="Repository as owner/name, e.g. uday/neo.", pattern=r"^[^/]+/[^/]+$")
    ],
    head_branch: Annotated[
        str, Field(description="New branch name to create for the fix.", min_length=1)
    ],
    title: Annotated[str, Field(description="Pull request title.", min_length=1, max_length=256)],
    body: Annotated[str, Field(description="Pull request description (markdown).")],
    files: Annotated[
        dict[str, str],
        Field(description="Map of file path -> full new file content to commit."),
    ],
    base_branch: Annotated[str, Field(description="Branch to merge into.")] = "main",
) -> dict[str, Any]:
    """Open a remediation pull request: create a branch, commit the given files, open the PR.

    `files` replaces each path's entire content; the model should supply the complete
    intended file, not a diff.
    """
    if MOCK_MODE:
        return {"status": "mock", "repo": repo, "head_branch": head_branch,
                "files_changed": list(files), "pull_request_url": f"https://github.com/{repo}/pull/0"}

    token = os.environ["GITHUB_TOKEN"]
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    with httpx.Client(base_url=f"{GITHUB_API}/repos/{repo}", headers=headers, timeout=HTTP_TIMEOUT) as gh:
        base_sha = gh.get(f"/git/ref/heads/{base_branch}").raise_for_status().json()["object"]["sha"]
        gh.post("/git/refs", json={"ref": f"refs/heads/{head_branch}", "sha": base_sha}).raise_for_status()

        import base64
        for path, content in files.items():
            existing = gh.get(f"/contents/{path}", params={"ref": head_branch})
            payload: dict[str, Any] = {
                "message": f"Neo remediation: update {path}",
                "content": base64.b64encode(content.encode()).decode(),
                "branch": head_branch,
            }
            if existing.status_code == 200:
                payload["sha"] = existing.json()["sha"]
            gh.put(f"/contents/{path}", json=payload).raise_for_status()

        pr = gh.post("/pulls", json={"title": title, "body": body,
                                     "head": head_branch, "base": base_branch}).raise_for_status().json()

    return {"status": "created", "repo": repo, "head_branch": head_branch,
            "files_changed": list(files), "pull_request_url": pr["html_url"]}


# ---------------------------------------------------------------------------
# RESOURCES
# ---------------------------------------------------------------------------

def _fetch_kev() -> dict[str, Any]:
    """Fetch and cache the CISA KEV catalog."""
    if MOCK_MODE:
        return {"title": "CISA KEV (mock)", "count": 1, "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
             "vulnerabilityName": "Apache Log4j2 RCE", "dateAdded": "2021-12-10",
             "knownRansomwareCampaignUse": "Known"}]}

    if _kev_cache["data"] and (time.time() - _kev_cache["fetched_at"]) < KEV_CACHE_TTL:
        return _kev_cache["data"]

    data = httpx.get(KEV_FEED_URL, timeout=HTTP_TIMEOUT).raise_for_status().json()
    _kev_cache.update(data=data, fetched_at=time.time())
    return data


@mcp.resource("kev://catalog", mime_type="application/json",
              description="Full CISA Known Exploited Vulnerabilities (KEV) catalog.")
def kev_catalog() -> str:
    return json.dumps(_fetch_kev())


@mcp.resource("kev://entry/{cve_id}", mime_type="application/json",
              description="A single CISA KEV entry by CVE ID, or a not-found marker.")
def kev_entry(cve_id: str) -> str:
    catalog = _fetch_kev()
    for entry in catalog.get("vulnerabilities", []):
        if entry.get("cveID", "").upper() == cve_id.upper():
            return json.dumps(entry)
    return json.dumps({"cve_id": cve_id, "in_kev": False})


@mcp.resource("epss://score/{cve_id}", mime_type="application/json",
              description="EPSS exploitation-probability score and percentile for a CVE.")
def epss_score(cve_id: str) -> str:
    if MOCK_MODE:
        return json.dumps({"cve": cve_id, "epss": 0.97412, "percentile": 0.99987})
    resp = httpx.get(EPSS_API_URL, params={"cve": cve_id}, timeout=HTTP_TIMEOUT).raise_for_status().json()
    rows = resp.get("data", [])
    if not rows:
        return json.dumps({"cve": cve_id, "epss": None, "percentile": None, "found": False})
    row = rows[0]
    return json.dumps({"cve": cve_id, "epss": float(row["epss"]), "percentile": float(row["percentile"])})


@mcp.resource("scan://results/{scan_id}", mime_type="application/json",
              description="Full findings for a prior run_vulnerability_scan call.")
def scan_results(scan_id: str) -> str:
    record = _SCAN_STORE.get(scan_id)
    if record is None:
        return json.dumps({"scan_id": scan_id, "error": "not_found"})
    return json.dumps(record)


# ---------------------------------------------------------------------------
# PROMPTS
# Triage and remediation templates — the third MCP primitive.
# The model fills in the arguments; the prompt body is what gets sent to Claude.
# ---------------------------------------------------------------------------

@mcp.prompt()
def triage_finding(
    cve_id: Annotated[str, Field(description="CVE identifier, e.g. CVE-2021-44228.")],
    title: Annotated[str, Field(description="Short vulnerability title.")],
    tier: Annotated[str, Field(description="Risk tier: P1 / P2 / P3 / P4.")],
    risk_score: Annotated[float, Field(description="Composite risk score 0–100.")],
    resource_id: Annotated[str, Field(description="Affected resource (instance ID, ARN, hostname).")],
    exposure: Annotated[str, Field(description="Network exposure: public | internal | isolated | unknown.")],
    in_kev: Annotated[bool, Field(description="True if the CVE is on the CISA Known Exploited Vulnerabilities list.")] = False,
    epss: Annotated[float | None, Field(description="EPSS 30-day exploitation probability (0–1), or null if unavailable.")] = None,
) -> str:
    """Triage a scored vulnerability finding and recommend an action."""
    kev_line = "WARNING: This CVE is on the CISA KEV — it is actively exploited in the wild.\n" if in_kev else ""
    epss_line = f"EPSS 30-day exploitation probability: {epss:.1%}.\n" if epss is not None else ""
    return (
        f"Triage the following vulnerability and recommend an action.\n\n"
        f"CVE:        {cve_id}\n"
        f"Title:      {title}\n"
        f"Tier:       {tier}  (risk score {risk_score}/100)\n"
        f"Resource:   {resource_id}  (exposure: {exposure})\n"
        f"{kev_line}{epss_line}\n"
        "Provide:\n"
        "1. A one-paragraph plain-language summary of the risk for a non-security engineer.\n"
        "2. Recommended action: patch immediately / schedule within SLA / accept risk / investigate further.\n"
        "3. Suggested SLA (hours / days / weeks) justified by tier and exposure.\n"
        "4. Compensating controls that reduce real-world risk while the patch is pending."
    )


@mcp.prompt()
def remediation_plan(
    cve_id: Annotated[str, Field(description="CVE identifier.")],
    title: Annotated[str, Field(description="Short vulnerability title.")],
    package_name: Annotated[str, Field(description="Name of the vulnerable package (e.g. log4j-core).")],
    fixed_version: Annotated[str, Field(description="First safe version to upgrade to.")],
    resource_id: Annotated[str, Field(description="Affected resource identifier.")],
    resource_type: Annotated[str, Field(description="Resource type, e.g. AWS_EC2_INSTANCE.")],
) -> str:
    """Generate a step-by-step remediation plan for a vulnerability finding."""
    return (
        f"Generate a step-by-step remediation plan for the following finding.\n\n"
        f"CVE:              {cve_id}\n"
        f"Title:            {title}\n"
        f"Vulnerable pkg:   {package_name}  →  fix in {fixed_version}\n"
        f"Affected resource:{resource_id}  ({resource_type})\n\n"
        "Include:\n"
        "1. Pre-remediation checklist: backup, rollback plan, test-environment validation.\n"
        "2. Exact upgrade/patch commands for the affected OS or runtime.\n"
        "3. Validation steps to confirm the fix (version check + scanner re-run command).\n"
        "4. Rollback steps if the patch causes a regression.\n"
        "5. A Terraform or Ansible snippet to codify the fix if applicable."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    transport = os.getenv("NEO_MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=transport)  # "streamable-http" or "sse"
