"""
Project Neo — MCP Server
========================
Exposes Neo's multi-cloud vulnerability-management pipeline over the Model
Context Protocol using the official MCP Python SDK (FastMCP).

TOOLS (actions / side-effects)
-------------------------------
AWS discovery
  pull_aws_inspector_findings   AWS Inspector v2 per account/region
  pull_aws_security_hub_findings  Security Hub aggregated findings

Azure discovery
  pull_azure_defender_findings  Defender for Cloud sub-assessments

GCP discovery
  pull_gcp_scc_findings         Security Command Center findings

On-prem scanners
  run_nessus_scan               Nessus Professional / Essentials
  run_qualys_scan               Qualys VMDR
  run_rapid7_scan               Rapid7 InsightVM

Testing
  load_mock_scan                Load a local mock fixture file (mock mode only)

Analysis
  score_findings                Enrich (EPSS/KEV) + risk-score a stored scan

Remediation
  create_github_remediation_pr  Open a fix PR on GitHub

RESOURCES (read-only context)
------------------------------
  kev://catalog                 Full CISA KEV catalog (~1 MB JSON, cached 6 h)
  kev://entry/{cve_id}          Single KEV entry
  epss://score/{cve_id}         FIRST.org EPSS probability + percentile
  scan://results/{scan_id}      Raw findings from any discovery tool
  scored://results/{scan_id}    Risk-scored findings (tier, score, breakdown)
  context://map/{scan_id}       Asset context used during a score_findings run

PROMPTS (templates for the orchestrating agent)
-----------------------------------------------
  triage_finding                Risk summary + action recommendation
  remediation_plan              Step-by-step fix instructions
  score_explanation             Walk through the risk math for one finding
  cloud_risk_summary            Executive summary across a cloud account/scan

SETUP
-----
  pip install -e ".[mcp]"               (from the Neo/ repo root)
  NEO_MOCK_MODE=true python neo_mcp_server.py
  uv run mcp dev neo_mcp_server.py      (MCP Inspector UI)

ENVIRONMENT VARIABLES
---------------------
  NEO_MOCK_MODE         "true" (default) — no credentials needed
  NEO_MCP_TRANSPORT     stdio (default) | streamable-http | sse
  NEO_HTTP_TIMEOUT      seconds (default 30)
  GITHUB_TOKEN          PAT with repo scope
  AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
  GOOGLE_APPLICATION_CREDENTIALS       path to GCP service-account JSON
  NESSUS_URL / NESSUS_ACCESS_KEY / NESSUS_SECRET_KEY
  QUALYS_URL / QUALYS_USERNAME / QUALYS_PASSWORD
  RAPID7_URL / RAPID7_USERNAME / RAPID7_PASSWORD
  AWS credentials via the standard boto3 chain (env / profile / role)
"""

import json
import os
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import httpx
from pydantic import Field

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# neo_core bridge — import all adapters once at startup
# ---------------------------------------------------------------------------

from neo_core import (
    aws_inspector as _aws_inspector,
    aws_securityhub as _aws_securityhub,
    azure_defender as _azure_defender,
    gcp_scc as _gcp_scc,
    nessus as _nessus,
    qualys as _qualys,
    rapid7 as _rapid7,
    enrich as _enrich,
    risk_engine as _risk_engine,
)
from neo_core.models import AssetContext, Finding as NeoFinding

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}
HTTP_TIMEOUT: float = float(os.getenv("NEO_HTTP_TIMEOUT", "30"))

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
GITHUB_API   = "https://api.github.com"
KEV_CACHE_TTL = 6 * 60 * 60

mcp = FastMCP("neo")

# ---------------------------------------------------------------------------
# Enums — tight JSON-schema constraints the orchestrating agent must respect
# ---------------------------------------------------------------------------

class Scanner(str, Enum):
    nessus = "nessus"
    qualys = "qualys"
    rapid7 = "rapid7"


class Severity(str, Enum):
    critical      = "critical"
    high          = "high"
    medium        = "medium"
    low           = "low"
    informational = "informational"


class CloudProvider(str, Enum):
    aws    = "aws"
    azure  = "azure"
    gcp    = "gcp"
    onprem = "onprem"


# ---------------------------------------------------------------------------
# In-memory stores
# Swap for DynamoDB / S3 in production.
# Resource handlers are the ONLY readers — tools write, resources read.
# ---------------------------------------------------------------------------

_SCAN_STORE:    dict[str, dict[str, Any]] = {}  # scan_id -> raw findings record
_SCORED_STORE:  dict[str, dict[str, Any]] = {}  # scan_id -> scored findings record
_CONTEXT_STORE: dict[str, dict[str, Any]] = {}  # scan_id -> context map used for scoring
_kev_cache:     dict[str, Any] = {"data": None, "fetched_at": 0.0}

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sev_breakdown(findings: list[NeoFinding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1
    return counts


def _store_scan(scan_id: str, source: str, findings: list[NeoFinding], **meta) -> dict[str, Any]:
    """Serialise findings into _SCAN_STORE and return the compact tool response."""
    _SCAN_STORE[scan_id] = {
        "scan_id":       scan_id,
        "source":        source,
        "scanned_at":    _now_iso(),
        "finding_count": len(findings),
        "findings":      [f.model_dump() for f in findings],
        **meta,
    }
    return {
        "scan_id":          scan_id,
        "source":           source,
        "finding_count":    len(findings),
        "severity_breakdown": _sev_breakdown(findings),
        "results_resource": f"scan://results/{scan_id}",
        **meta,
    }


def _build_default_contexts(findings: list[NeoFinding]) -> dict[str, AssetContext]:
    """Return a minimal context map when no external context source is available.
    Mock mode uses heuristics; real mode defaults to exposure=unknown."""
    contexts: dict[str, AssetContext] = {}
    for f in findings:
        if f.resource_id in contexts:
            continue
        if MOCK_MODE:
            is_web = any(kw in f.resource_id.lower() for kw in ("web", "public", "prod"))
            contexts[f.resource_id] = AssetContext(
                resource_id=f.resource_id,
                exposure="public"   if is_web else "internal",
                criticality="critical" if is_web else "medium",
            )
        else:
            contexts[f.resource_id] = AssetContext(resource_id=f.resource_id)
    return contexts


# ---------------------------------------------------------------------------
# TOOLS — Testing
# ---------------------------------------------------------------------------

_ONPREM_SOURCE_PREFIXES = {"nessus": "nessus-", "qualys": "qualys-", "rapid7": "r7-"}


@mcp.tool()
def load_mock_scan(
    file_path: Annotated[str, Field(description=(
        "Path to a mock fixture file in {findings, contexts, enrichments} format "
        "(same shape as Neo Core/examples/mock_findings*.json). Relative paths are "
        "resolved against the Neo/ repo root."
    ))],
    source_filter: Annotated[Optional[str], Field(description=(
        "Restrict to one source: aws | azure | gcp | nessus | qualys | rapid7. "
        "Omit to load every finding in the file."
    ))] = None,
) -> dict[str, Any]:
    """Load findings from a local mock fixture file into the scan store for testing.

    Only usable when NEO_MOCK_MODE is true. Lets you exercise score_findings against
    a richer, hand-built fixture instead of each discovery tool's small built-in demo
    dataset. Returns a scan_id usable with score_findings exactly like a live pull.
    """
    if not MOCK_MODE:
        return {"error": "load_mock_scan is only available when NEO_MOCK_MODE=true"}

    path = Path(file_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent.parent / file_path
    if not path.exists():
        return {"error": f"file not found: {path}"}

    data = json.loads(path.read_text())
    raw_findings = data.get("findings", [])

    if source_filter:
        sf = source_filter.lower()
        if sf in {"aws", "azure", "gcp"}:
            raw_findings = [f for f in raw_findings if f.get("cloud_provider") == sf]
        elif sf in _ONPREM_SOURCE_PREFIXES:
            prefix = _ONPREM_SOURCE_PREFIXES[sf]
            raw_findings = [f for f in raw_findings if f.get("finding_id", "").startswith(prefix)]
        else:
            return {"error": f"unknown source_filter: {source_filter!r}. "
                              f"Expected one of: aws, azure, gcp, nessus, qualys, rapid7."}

    if not raw_findings:
        return {"error": "no findings matched", "file": str(path), "source_filter": source_filter}

    findings = [NeoFinding(**f) for f in raw_findings]
    scan_id  = f"mock-{source_filter or 'all'}-{int(time.time())}"
    return _store_scan(scan_id, f"mock-fixture:{source_filter or 'all'}", findings, file=str(path))


# ---------------------------------------------------------------------------
# TOOLS — AWS
# ---------------------------------------------------------------------------

@mcp.tool()
def pull_aws_inspector_findings(
    account_id: Annotated[str,       Field(description="12-digit AWS account ID.",  pattern=r"^\d{12}$")],
    region:     Annotated[str,       Field(description="AWS region, e.g. us-east-1.", min_length=1)],
    severities: Annotated[list[Severity], Field(description="Severity levels to include.")] = [Severity.critical, Severity.high],
    max_results: Annotated[int,      Field(description="Maximum findings to return.", ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Pull active CVE findings from AWS Inspector v2 for a specific account and region.

    Returns a compact summary. Fetch the full finding set via scan://results/{scan_id}.
    """
    findings = _aws_inspector.pull_findings(region=region, max_results=max_results)
    scan_id  = f"inspector-{account_id}-{int(time.time())}"
    return _store_scan(scan_id, "aws-inspector", findings, account_id=account_id, region=region)


@mcp.tool()
def pull_aws_security_hub_findings(
    account_id:  Annotated[str,       Field(description="12-digit AWS account ID.", pattern=r"^\d{12}$")],
    region:      Annotated[str,       Field(description="AWS region, e.g. us-east-1.", min_length=1)],
    max_results: Annotated[int,       Field(description="Maximum findings to return.", ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Pull active CVE findings aggregated in AWS Security Hub for an account and region."""
    findings = _aws_securityhub.pull_findings(region=region, max_results=max_results)
    scan_id  = f"securityhub-{account_id}-{int(time.time())}"
    return _store_scan(scan_id, "aws-security-hub", findings, account_id=account_id, region=region)


# ---------------------------------------------------------------------------
# TOOLS — Azure
# ---------------------------------------------------------------------------

@mcp.tool()
def pull_azure_defender_findings(
    subscription_id: Annotated[str, Field(description="Azure subscription ID (UUID format).",
                                          min_length=36, max_length=36)],
    max_results:     Annotated[int, Field(description="Maximum findings to return.", ge=1, le=1000)] = 200,
) -> dict[str, Any]:
    """Pull CVE-level vulnerability findings from Microsoft Defender for Cloud.

    Credentials are read from AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
    environment variables, or DefaultAzureCredential (managed identity, CLI login).
    Returns a compact summary; fetch full findings via scan://results/{scan_id}.
    """
    findings = _azure_defender.pull_findings(
        subscription_id=subscription_id,
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET"),
        max_results=max_results,
    )
    scan_id = f"azure-defender-{subscription_id[:8]}-{int(time.time())}"
    return _store_scan(scan_id, "azure-defender", findings, subscription_id=subscription_id)


# ---------------------------------------------------------------------------
# TOOLS — GCP
# ---------------------------------------------------------------------------

@mcp.tool()
def pull_gcp_scc_findings(
    project_id:  Annotated[str, Field(description="GCP project ID.", min_length=1)],
    max_results: Annotated[int, Field(description="Maximum findings to return.", ge=1, le=1000)] = 200,
) -> dict[str, Any]:
    """Pull CVE-level vulnerability findings from Google Cloud Security Command Center.

    Credentials are read from GOOGLE_APPLICATION_CREDENTIALS or Application Default Credentials.
    Returns a compact summary; fetch full findings via scan://results/{scan_id}.
    """
    findings = _gcp_scc.pull_findings(
        project_id=project_id,
        credentials_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        max_results=max_results,
    )
    scan_id = f"gcp-scc-{project_id}-{int(time.time())}"
    return _store_scan(scan_id, "gcp-scc", findings, project_id=project_id)


# ---------------------------------------------------------------------------
# TOOLS — On-prem scanners
# Each scanner gets its own tool (tight schema, distinct auth params).
# A single combined tool would over-broaden the schema — see CLAUDE.md.
# ---------------------------------------------------------------------------

@mcp.tool()
def run_nessus_scan(
    scanner_url: Annotated[str, Field(description="Nessus base URL, e.g. https://nessus-host:8834.")],
    scan_id_hint: Annotated[int | None, Field(description="Specific Nessus scan ID to export. "
                                               "Omit to use the most recent completed scan.")] = None,
    max_results: Annotated[int, Field(description="Maximum findings to return.", ge=1, le=10000)] = 2000,
) -> dict[str, Any]:
    """Export findings from a Nessus scan (most recent completed scan if scan_id_hint omitted).

    Credentials: NESSUS_ACCESS_KEY / NESSUS_SECRET_KEY environment variables.
    Returns summary + scan_id; fetch full findings via scan://results/{scan_id}.
    """
    findings = _nessus.pull_findings(
        scanner_url=scanner_url,
        access_key=os.getenv("NESSUS_ACCESS_KEY"),
        secret_key=os.getenv("NESSUS_SECRET_KEY"),
        scan_id=scan_id_hint,
        max_results=max_results,
    )
    sid = f"nessus-{int(time.time())}"
    return _store_scan(sid, "nessus", findings, scanner_url=scanner_url)


@mcp.tool()
def run_qualys_scan(
    scanner_url:  Annotated[str, Field(description="Qualys API base URL, e.g. https://qualysapi.qualys.com.")],
    severity_min: Annotated[int, Field(description="Minimum Qualys severity to include (1–5). "
                                        "3 = Medium and above.", ge=1, le=5)] = 3,
    max_results:  Annotated[int, Field(description="Maximum findings to return.", ge=1, le=10000)] = 2000,
) -> dict[str, Any]:
    """Pull active vulnerability detections from Qualys VMDR.

    Credentials: QUALYS_USERNAME / QUALYS_PASSWORD environment variables.
    Returns summary + scan_id; fetch full findings via scan://results/{scan_id}.
    """
    findings = _qualys.pull_findings(
        scanner_url=scanner_url,
        username=os.getenv("QUALYS_USERNAME"),
        password=os.getenv("QUALYS_PASSWORD"),
        severity_min=severity_min,
        max_results=max_results,
    )
    sid = f"qualys-{int(time.time())}"
    return _store_scan(sid, "qualys", findings, scanner_url=scanner_url)


@mcp.tool()
def run_rapid7_scan(
    scanner_url: Annotated[str, Field(description="InsightVM console URL, e.g. https://console:3780.")],
    max_results: Annotated[int, Field(description="Maximum findings to return.", ge=1, le=10000)] = 2000,
) -> dict[str, Any]:
    """Pull vulnerability findings from Rapid7 InsightVM across all assets.

    Credentials: RAPID7_USERNAME / RAPID7_PASSWORD environment variables.
    Returns summary + scan_id; fetch full findings via scan://results/{scan_id}.
    """
    findings = _rapid7.pull_findings(
        scanner_url=scanner_url,
        username=os.getenv("RAPID7_USERNAME"),
        password=os.getenv("RAPID7_PASSWORD"),
        max_results=max_results,
    )
    sid = f"rapid7-{int(time.time())}"
    return _store_scan(sid, "rapid7", findings, scanner_url=scanner_url)


# ---------------------------------------------------------------------------
# TOOLS — Analysis
# ---------------------------------------------------------------------------

@mcp.tool()
def score_findings(
    scan_id: Annotated[str, Field(description="scan_id returned by any discovery tool.")],
    context_overrides: Annotated[
        dict[str, dict[str, Any]],
        Field(description=(
            "Optional per-resource context. Map resource_id → "
            "{exposure: public|internal|isolated|unknown, "
            " criticality: critical|high|medium|low|unknown, "
            " compensating_controls: 0.0–1.0}. "
            "Resources not listed fall back to defaults."
        )),
    ] = {},
) -> dict[str, Any]:
    """Enrich findings with EPSS + CISA KEV and compute composite risk scores.

    Run after any discovery tool. Returns a ranked summary (top 10 by risk score).
    Full scored results available via scored://results/{scan_id}.
    Context for each resource is resolved from context_overrides first, then defaults.
    """
    record = _SCAN_STORE.get(scan_id)
    if record is None:
        return {"error": "scan_id not found", "scan_id": scan_id}

    # Reconstruct NeoFinding objects from stored dicts
    raw_findings: list[NeoFinding] = [NeoFinding(**f) for f in record["findings"]]
    if not raw_findings:
        return {"error": "no findings in scan", "scan_id": scan_id}

    # Build context map — overrides win, then cloud-appropriate defaults
    contexts = _build_default_contexts(raw_findings)
    for rid, override in (context_overrides or {}).items():
        contexts[rid] = AssetContext(resource_id=rid, **override)

    # Enrich with EPSS + KEV
    cve_ids = [f.cve_id for f in raw_findings if f.cve_id]
    enrichments = _enrich.build_enrichments(cve_ids)

    # Score
    scored = _risk_engine.score_all(raw_findings, contexts, enrichments)

    # Persist
    _SCORED_STORE[scan_id] = {
        "scan_id":       scan_id,
        "scored_at":     _now_iso(),
        "finding_count": len(scored),
        "scored_findings": [s.model_dump() for s in scored],
    }
    _CONTEXT_STORE[scan_id] = {
        rid: ctx.model_dump() for rid, ctx in contexts.items()
    }

    # Tier summary
    tier_counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for s in scored:
        tier_counts[s.tier] = tier_counts.get(s.tier, 0) + 1

    top_10 = [
        {
            "rank":        i + 1,
            "tier":        s.tier,
            "risk_score":  s.risk_score,
            "cve_id":      s.finding.cve_id,
            "title":       s.finding.title,
            "resource_id": s.finding.resource_id,
            "in_kev":      s.enrichment.kev,
            "epss":        s.enrichment.epss,
        }
        for i, s in enumerate(scored[:10])
    ]

    return {
        "scan_id":         scan_id,
        "total_findings":  len(scored),
        "tier_breakdown":  tier_counts,
        "top_10":          top_10,
        "scored_resource": f"scored://results/{scan_id}",
        "context_resource": f"context://map/{scan_id}",
    }


# ---------------------------------------------------------------------------
# TOOLS — Remediation
# ---------------------------------------------------------------------------

@mcp.tool()
def create_github_remediation_pr(
    repo:        Annotated[str, Field(description="Repository as owner/name, e.g. acme/api.",
                                      pattern=r"^[^/]+/[^/]+$")],
    head_branch: Annotated[str, Field(description="New branch name to create for the fix.", min_length=1)],
    title:       Annotated[str, Field(description="Pull request title.", min_length=1, max_length=256)],
    body:        Annotated[str, Field(description="Pull request description (markdown).")],
    files:       Annotated[dict[str, str],
                           Field(description="Map of file path → full new file content to commit.")],
    base_branch: Annotated[str, Field(description="Branch to merge into.")] = "main",
) -> dict[str, Any]:
    """Open a remediation pull request: create a branch, commit files, open the PR.

    Supply the complete intended content for each file (not a diff).
    """
    if MOCK_MODE:
        return {
            "status": "mock", "repo": repo, "head_branch": head_branch,
            "files_changed": list(files),
            "pull_request_url": f"https://github.com/{repo}/pull/0",
        }

    import base64

    token   = os.environ["GITHUB_TOKEN"]
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    with httpx.Client(base_url=f"{GITHUB_API}/repos/{repo}",
                      headers=headers, timeout=HTTP_TIMEOUT) as gh:
        base_sha = gh.get(f"/git/ref/heads/{base_branch}").raise_for_status().json()["object"]["sha"]
        gh.post("/git/refs", json={"ref": f"refs/heads/{head_branch}", "sha": base_sha}).raise_for_status()

        for path, content in files.items():
            existing = gh.get(f"/contents/{path}", params={"ref": head_branch})
            payload: dict[str, Any] = {
                "message": f"Neo remediation: update {path}",
                "content": base64.b64encode(content.encode()).decode(),
                "branch":  head_branch,
            }
            if existing.status_code == 200:
                payload["sha"] = existing.json()["sha"]
            gh.put(f"/contents/{path}", json=payload).raise_for_status()

        pr = gh.post("/pulls", json={"title": title, "body": body,
                                     "head": head_branch, "base": base_branch}).raise_for_status().json()

    return {
        "status":           "created",
        "repo":             repo,
        "head_branch":      head_branch,
        "files_changed":    list(files),
        "pull_request_url": pr["html_url"],
    }


# ---------------------------------------------------------------------------
# RESOURCES — Threat intel
# ---------------------------------------------------------------------------

def _fetch_kev() -> dict[str, Any]:
    if MOCK_MODE:
        return {
            "title": "CISA KEV (mock)", "count": 2,
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
                 "vulnerabilityName": "Apache Log4j2 RCE", "dateAdded": "2021-12-10",
                 "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2024-3094", "vendorProject": "Tukaani", "product": "XZ Utils",
                 "vulnerabilityName": "XZ Utils Backdoor", "dateAdded": "2024-03-29",
                 "knownRansomwareCampaignUse": "Unknown"},
            ],
        }
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
              description="Single CISA KEV entry by CVE ID, or a not-found marker.")
def kev_entry(cve_id: str) -> str:
    catalog = _fetch_kev()
    for entry in catalog.get("vulnerabilities", []):
        if entry.get("cveID", "").upper() == cve_id.upper():
            return json.dumps(entry)
    return json.dumps({"cve_id": cve_id, "in_kev": False})


@mcp.resource("epss://score/{cve_id}", mime_type="application/json",
              description="FIRST.org EPSS exploitation-probability score and percentile for a CVE.")
def epss_score(cve_id: str) -> str:
    if MOCK_MODE:
        return json.dumps({"cve": cve_id, "epss": 0.97412, "percentile": 0.99987})
    resp = httpx.get(EPSS_API_URL, params={"cve": cve_id}, timeout=HTTP_TIMEOUT).raise_for_status().json()
    rows = resp.get("data", [])
    if not rows:
        return json.dumps({"cve": cve_id, "epss": None, "percentile": None, "found": False})
    row = rows[0]
    return json.dumps({"cve": cve_id, "epss": float(row["epss"]), "percentile": float(row["percentile"])})


# ---------------------------------------------------------------------------
# RESOURCES — Scan and scored results
# ---------------------------------------------------------------------------

@mcp.resource("scan://results/{scan_id}", mime_type="application/json",
              description="Full raw findings from any discovery tool (Inspector, Defender, Nessus, etc.).")
def scan_results(scan_id: str) -> str:
    record = _SCAN_STORE.get(scan_id)
    if record is None:
        return json.dumps({"scan_id": scan_id, "error": "not_found"})
    return json.dumps(record, default=str)


@mcp.resource("scored://results/{scan_id}", mime_type="application/json",
              description="Risk-scored findings for a scan. "
                          "Each entry includes tier (P1-P4), risk_score (0-100), "
                          "and a full breakdown of likelihood × impact × exposure_factor.")
def scored_results(scan_id: str) -> str:
    record = _SCORED_STORE.get(scan_id)
    if record is None:
        return json.dumps({"scan_id": scan_id, "error": "not_scored_yet",
                           "hint": "Call score_findings(scan_id) first."})
    return json.dumps(record, default=str)


@mcp.resource("context://map/{scan_id}", mime_type="application/json",
              description="Asset context map used during score_findings: "
                          "exposure, criticality, and compensating controls per resource.")
def context_map(scan_id: str) -> str:
    record = _CONTEXT_STORE.get(scan_id)
    if record is None:
        return json.dumps({"scan_id": scan_id, "error": "not_found"})
    return json.dumps(record, default=str)


# ---------------------------------------------------------------------------
# PROMPTS — Triage and remediation (original, kept)
# ---------------------------------------------------------------------------

@mcp.prompt()
def triage_finding(
    cve_id:      Annotated[str,        Field(description="CVE identifier, e.g. CVE-2021-44228.")],
    title:       Annotated[str,        Field(description="Short vulnerability title.")],
    tier:        Annotated[str,        Field(description="Risk tier: P1 / P2 / P3 / P4.")],
    risk_score:  Annotated[float,      Field(description="Composite risk score 0–100.")],
    resource_id: Annotated[str,        Field(description="Affected resource (instance ID, ARN, hostname).")],
    exposure:    Annotated[str,        Field(description="Network exposure: public|internal|isolated|unknown.")],
    cloud:       Annotated[str,        Field(description="Cloud provider: aws|azure|gcp|onprem.")] = "aws",
    in_kev:      Annotated[bool,       Field(description="True if on the CISA KEV list.")] = False,
    epss:        Annotated[float | None, Field(description="EPSS 30-day exploitation probability (0–1).")] = None,
) -> str:
    """Triage a scored vulnerability finding and recommend an action."""
    kev_line  = "WARNING: This CVE is on the CISA KEV — actively exploited in the wild.\n" if in_kev else ""
    epss_line = f"EPSS 30-day exploitation probability: {epss:.1%}.\n" if epss is not None else ""
    return (
        f"Triage the following vulnerability and recommend an action.\n\n"
        f"CVE:          {cve_id}\n"
        f"Title:        {title}\n"
        f"Tier:         {tier}  (risk score {risk_score}/100)\n"
        f"Cloud:        {cloud}\n"
        f"Resource:     {resource_id}  (exposure: {exposure})\n"
        f"{kev_line}{epss_line}\n"
        "Provide:\n"
        "1. A one-paragraph plain-language summary of the risk for a non-security engineer.\n"
        "2. Recommended action: patch immediately / schedule within SLA / accept risk / investigate.\n"
        "3. Suggested SLA (hours / days / weeks) justified by tier and exposure.\n"
        "4. Compensating controls that reduce real-world risk while the patch is pending."
    )


@mcp.prompt()
def remediation_plan(
    cve_id:        Annotated[str, Field(description="CVE identifier.")],
    title:         Annotated[str, Field(description="Short vulnerability title.")],
    package_name:  Annotated[str, Field(description="Vulnerable package, e.g. log4j-core.")],
    fixed_version: Annotated[str, Field(description="First safe version to upgrade to.")],
    resource_id:   Annotated[str, Field(description="Affected resource identifier.")],
    resource_type: Annotated[str, Field(description="Resource type, e.g. AWS_EC2_INSTANCE.")],
    cloud:         Annotated[str, Field(description="Cloud provider: aws|azure|gcp|onprem.")] = "aws",
) -> str:
    """Generate a step-by-step remediation plan for a vulnerability finding."""
    return (
        f"Generate a step-by-step remediation plan for the following finding.\n\n"
        f"CVE:              {cve_id}\n"
        f"Title:            {title}\n"
        f"Vulnerable pkg:   {package_name}  →  fix in {fixed_version}\n"
        f"Cloud / platform: {cloud}\n"
        f"Affected resource:{resource_id}  ({resource_type})\n\n"
        "Include:\n"
        "1. Pre-remediation checklist: backup, rollback plan, test-environment validation.\n"
        "2. Exact upgrade/patch commands for the affected OS or runtime.\n"
        "3. Validation steps to confirm the fix (version check + scanner re-run command).\n"
        "4. Rollback steps if the patch causes a regression.\n"
        "5. A Terraform or Ansible snippet to codify the fix if applicable."
    )


# ---------------------------------------------------------------------------
# PROMPTS — Analysis (new)
# ---------------------------------------------------------------------------

@mcp.prompt()
def score_explanation(
    cve_id:           Annotated[str,   Field(description="CVE identifier.")],
    tier:             Annotated[str,   Field(description="Risk tier: P1 / P2 / P3 / P4.")],
    risk_score:       Annotated[float, Field(description="Composite risk score 0–100.")],
    likelihood:       Annotated[float, Field(description="Likelihood factor (0–1). Driven by EPSS / KEV.")],
    impact:           Annotated[float, Field(description="Impact factor (0–1). (CVSS/10) × criticality weight.")],
    exposure_factor:  Annotated[float, Field(description="Exposure factor (0–1). Network exposure × (1 − controls).")],
    criticality:      Annotated[str,   Field(description="Asset business criticality label.")] = "unknown",
    exposure:         Annotated[str,   Field(description="Network exposure label.")] = "unknown",
    in_kev:           Annotated[bool,  Field(description="True if on the CISA KEV list.")] = False,
) -> str:
    """Explain the risk math behind a single scored finding in plain language."""
    kev_note = "Because this CVE is on the CISA KEV, likelihood is floored at 0.85 regardless of EPSS.\n" if in_kev else ""
    return (
        f"Explain the following risk score calculation to an engineer who is not familiar "
        f"with the Neo scoring model.\n\n"
        f"CVE:             {cve_id}\n"
        f"Tier:            {tier}\n"
        f"Risk score:      {risk_score}/100\n"
        f"Formula:         risk = likelihood × impact × exposure_factor × 100\n"
        f"  likelihood:    {likelihood:.4f}  (EPSS / KEV floor / exploit-available signal)\n"
        f"  impact:        {impact:.4f}       (CVSS/10 × criticality weight for '{criticality}')\n"
        f"  exposure:      {exposure_factor:.4f}      (exposure weight for '{exposure}' × (1 − compensating controls))\n"
        f"{kev_note}\n"
        "Tasks:\n"
        "1. Walk through the arithmetic step by step so an engineer can verify it.\n"
        "2. Identify which single factor has the biggest influence on this score.\n"
        "3. Suggest which factor the team can realistically reduce fastest "
        "(e.g. add a compensating control, reduce exposure by moving the service off the internet).\n"
        "4. Show what the new score and tier would be if that factor were improved by 50%."
    )


@mcp.prompt()
def cloud_risk_summary(
    cloud_provider:  Annotated[str, Field(description="Cloud provider: aws|azure|gcp|onprem.")],
    scan_id:         Annotated[str, Field(description="scan_id from a discovery tool.")],
    total_findings:  Annotated[int, Field(description="Total scored findings.", ge=0)],
    p1_count:        Annotated[int, Field(description="Number of P1 (critical) findings.", ge=0)],
    p2_count:        Annotated[int, Field(description="Number of P2 (high) findings.", ge=0)],
    p3_count:        Annotated[int, Field(description="Number of P3 (medium) findings.", ge=0)],
    top_cves:        Annotated[str, Field(description="Comma-separated list of the top 5 CVE IDs by risk score.")],
    account_or_project: Annotated[str, Field(description="AWS account ID, Azure subscription, GCP project, or scanner URL.")] = "",
) -> str:
    """Generate an executive risk summary for a cloud account or on-prem scan."""
    p4_count = max(0, total_findings - p1_count - p2_count - p3_count)
    acct_line = f"Account / project: {account_or_project}\n" if account_or_project else ""
    return (
        f"Write an executive risk summary for the following vulnerability scan.\n\n"
        f"Cloud platform:  {cloud_provider}\n"
        f"{acct_line}"
        f"Scan ID:         {scan_id}\n"
        f"Total findings:  {total_findings}\n"
        f"  P1 (critical): {p1_count}\n"
        f"  P2 (high):     {p2_count}\n"
        f"  P3 (medium):   {p3_count}\n"
        f"  P4 (low):      {p4_count}\n"
        f"Top CVEs by risk: {top_cves}\n\n"
        "Produce:\n"
        "1. A 3-sentence executive summary suitable for a CISO or board-level audience.\n"
        "2. A prioritised action list: what must be done in the next 24 h / 7 days / 30 days.\n"
        "3. A risk trend note — flag if any of the top CVEs are on the CISA KEV list "
        "or have EPSS > 0.5, and what that means for urgency.\n"
        "4. A suggested remediation ownership table: which team owns each P1 finding "
        "(infer from the resource type and cloud provider)."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    transport = os.getenv("NEO_MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=transport)
