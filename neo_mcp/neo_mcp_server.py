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
  track_remediation             Open + route items (path A/B/C), verify against a scan
  create_change_request         Path B: raise a ServiceNow change (plans, CIs, window)
  sync_change_approvals         Pull CAB outcomes from ServiceNow into items
  check_patch_gate              Is patching allowed right now, and on which hosts?
  mock_advance_change           Play the CAB against the mock (mock mode only)
  preview_control_impact        Path C what-if: score/tier with these controls, plus the tag
  draft_risk_exception          Path C: submit an exception draft for the risk owner
  create_controls_change_request  Path C: after approval, raise the ServiceNow change that
                                implements the controls (CAB approves, a person implements)

RESOURCES (read-only context)
------------------------------
  kev://catalog                 Full CISA KEV catalog (~1 MB JSON, cached 6 h)
  kev://entry/{cve_id}          Single KEV entry
  epss://score/{cve_id}         FIRST.org EPSS probability + percentile
  scan://results/{scan_id}      Raw findings from any discovery tool
  scored://results/{scan_id}    Risk-scored findings (tier, score, breakdown)
  context://map/{scan_id}       Asset context used during a score_findings run
  controls://catalog            Compensating controls that earn credit, with weights
  remediation://items           All tracked remediation items (state, path, SLA, change)
  remediation://item/{item_id}  One item: refs, scan evidence, audit history

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
  NEO_REMEDIATION_DB    SQLite file for remediation items (default neo_remediation.db;
                        shared with `neo remediate`)
  SNOW_INSTANCE_URL / SNOW_USERNAME / SNOW_PASSWORD   live ServiceNow (path B)
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
from datetime import datetime, timedelta, timezone
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
    changes as _changes,
    change_groups as _change_groups,
    closeout as _closeout,
    patcher as _patcher,
    controls as _controls,
    exceptions as _exceptions,
    servicenow as _servicenow,
)
from neo_core.models import AssetContext, Finding as NeoFinding, ScoredFinding
from neo_core.remediation import (
    Path as RemediationPath, RemediationItem, State as RemediationState, finding_key,
)
from neo_core.remediation_store import SqliteStore
from neo_core.servicenow import ChangeError, ChangeState

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
        "(same shape as neo_core/examples/mock_findings*.json). Relative paths are "
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
# TOOLS — Remediation tracking and Path B (host patching via ServiceNow)
#
# The agent may open items, raise changes and read approvals. It cannot approve a
# change, advance an item's state, or patch anything: CAB approval lives in
# ServiceNow and the patch executor re-checks it (see neo_core/changes.py).
# ---------------------------------------------------------------------------

REMEDIATION_DB = os.getenv("NEO_REMEDIATION_DB", "neo_remediation.db")
_ITEM_ID_PATTERN = r"^REM-[0-9A-F]{10}$"
_remediation_store: SqliteStore | None = None


def _store() -> SqliteStore:
    global _remediation_store
    if _remediation_store is None:
        _remediation_store = SqliteStore(REMEDIATION_DB)
    return _remediation_store


def _snow():
    # Shares the mock's state file with `neo remediate change ...` on the CLI.
    return _servicenow.get_client(REMEDIATION_DB + ".snow.json")


def _utc(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _item_row(i: RemediationItem) -> dict[str, Any]:
    return {
        "item_id": i.item_id, "cve_id": i.cve_id, "resource_id": i.resource_id,
        "package": i.package_name, "fixed_version": i.fixed_version, "tier": i.tier,
        "path": i.path.value, "state": i.state.value, "sla_due": i.sla_due,
        "change": i.refs.get("chg_number"), "escalated": i.escalated,
    }


@mcp.tool()
def track_remediation(
    scan_id: Annotated[str, Field(description="scan_id already passed to score_findings.")],
    scan_is_complete: Annotated[bool, Field(description=(
        "True only if this scan covered EVERY asset being tracked. When false (default) a finding "
        "can only close on a resource this scan reported something for, so a partial scan "
        "cannot mark other assets' findings as fixed."
    ))] = False,
) -> dict[str, Any]:
    """Open and route a remediation item per scored finding, and verify existing ones.

    Routes each finding to path A (code/image PR), B (host patch via ServiceNow change) or
    C (risk exception). Items whose finding is absent from this scan close as REMEDIATED;
    items still present after their window reopen and escalate. Safe to re-run per scan.
    """
    record = _SCORED_STORE.get(scan_id)
    if record is None:
        return {"error": "scan not scored yet", "hint": "Call score_findings(scan_id) first."}
    scored = [ScoredFinding.model_validate(s) for s in record["scored_findings"]]
    covered = None if scan_is_complete else {s.finding.resource_id for s in scored}
    r = _closeout.sync_scan(_store(), scored, scan_id, covered=covered)
    return {
        "scan_id": scan_id, "opened": r.opened, "remediated": r.remediated, "reopened": r.reopened,
        "rerouted": r.rerouted, "rescored": r.rescored, "not_covered": r.not_covered,
        "tag_drift": r.drifted, "tag_drift_cleared": r.drift_cleared,
        "items_resource": "remediation://items",
    }


@mcp.tool()
def create_change_request(
    item_id: Annotated[str, Field(description="Remediation item on path B.", pattern=_ITEM_ID_PATTERN)],
    implementation_plan: Annotated[str, Field(description=(
        "Numbered steps to apply the fix. Leave empty to use Neo's default."))] = "",
    backout_plan: Annotated[str, Field(description=(
        "Numbered rollback steps: snapshot first, then uninstall/undo, then restore. "
        "Leave empty to use Neo's default for the item's cloud."))] = "",
    test_plan: Annotated[str, Field(description=(
        "How success is verified: health check plus a targeted re-scan. Empty = default."))] = "",
    cis: Annotated[list[str], Field(description=(
        "CMDB CI names the change covers (a patch group). Must include the item's own host. "
        "Empty = just the item's host."))] = [],
    window_start: Annotated[str, Field(description=(
        "ISO-8601 start (UTC if no offset). Empty = tier default: P1 in 1h, others tomorrow."))] = "",
    window_end: Annotated[str, Field(description="ISO-8601 end. Empty = start + 4 hours.")] = "",
    assignment_group: Annotated[str, Field(description="ServiceNow group to assign. Optional.")] = "",
) -> dict[str, Any]:
    """Raise a ServiceNow change request to patch ONE item's host (path B), then wait for CAB.

    When several hosts need the same fix, prefer plan_change_groups + create_group_change_request:
    one change per fix, with production and non-production in separate changes.
    P1 findings become emergency changes; others are normal changes. The change needs
    implementation, rollback and test plans and a window. This does NOT approve or run
    anything -- CAB approves in ServiceNow; use sync_change_approvals to pull the outcome.
    """
    store = _store()
    item = store.get(item_id)
    if item is None:
        return {"error": f"no such item: {item_id}"}
    if cis and item.resource_id not in cis:
        return {"error": f"cis must include the item's own host {item.resource_id}"}
    try:
        start, end = _changes.default_window(item)
        if window_start:
            start = _utc(window_start)
            end = _utc(window_end) if window_end else start + timedelta(hours=4)
        req = _changes.build_request(item, cis or [item.resource_id], start, end,
                                     implementation_plan, backout_plan, test_plan,
                                     assignment_group or None)
        item = _changes.submit_change(store, _snow(), item_id, req)
    except (ValueError, ChangeError) as e:
        return {"error": str(e)}
    return {
        "item_id": item.item_id, "change_number": item.refs["chg_number"], "type": req.type,
        "state": item.state.value, "window_start": start.isoformat(), "window_end": end.isoformat(),
        "next": "CAB must approve in ServiceNow; then call sync_change_approvals.",
    }


@mcp.tool()
def sync_change_approvals() -> dict[str, Any]:
    """Pull change outcomes from ServiceNow into the items waiting on them. Read-only there.

    Patch changes (path B): approved + scheduled/implement -> item APPROVED; cancelled or
    rejected -> item back to PROPOSED so a new change can be raised.
    Controls changes (path C): compensating controls count as applied ONLY when the change
    has been closed successfully by the person who implemented it. A failed or cancelled
    change leaves the controls unapplied and frees the item for a new change.
    """
    try:
        client = _snow()
        r = _changes.sync_changes(_store(), client)
        x = _exceptions.sync_controls_changes(_store(), client)
    except ChangeError as e:
        return {"error": str(e)}
    return {"approved": r.approved, "declined": r.declined,
            "controls_applied": x.applied, "controls_change_failed": x.failed,
            "errors": {**r.errors, **x.errors}}


@mcp.tool()
def check_patch_gate(
    item_id: Annotated[str, Field(description="Remediation item on path B.", pattern=_ITEM_ID_PATTERN)],
) -> dict[str, Any]:
    """Report whether patching this item is allowed right now, and on which hosts.

    Read-only and informational: the patch executor re-checks ServiceNow itself at run time.
    Allowed only when the change is in Implement with approval granted, the time is inside
    the change window, and the host is on the change's own CI list.
    """
    item = _store().get(item_id)
    if item is None:
        return {"error": f"no such item: {item_id}"}
    try:
        g = _changes.execution_gate(_snow(), item)
    except ChangeError as e:
        return {"error": str(e)}
    order = _change_groups.precedence_gate(_store(), item)
    allowed = g.allowed and order.allowed
    return {"item_id": item_id, "allowed": allowed,
            "reason": g.reason if not g.allowed else order.reason,
            "instance_ids": g.instance_ids if allowed else [],
            "environment": item.environment, "precedence": order.reason}


@mcp.tool()
def plan_change_groups(
    max_hosts: Annotated[int, Field(ge=1, le=500, description="Most hosts per change; larger groups split.")] = _change_groups.MAX_HOSTS_PER_CHANGE,
) -> dict[str, Any]:
    """Group the path-B items waiting for a change: one change per fix, read-only.

    Grouping is code: same cloud, same package and fixed version, same environment. Production
    and non-production are ALWAYS separate changes, and non-production groups are listed first
    because production hosts cannot be patched until the same fix has run on non-production.
    The group's tier is its highest item tier (one P1 host makes it an emergency change).
    """
    groups = _change_groups.plan_groups(_store(), max_hosts=max_hosts)
    return {"groups": [g.summary() for g in groups],
            "next": "Raise non-production groups first with create_group_change_request(group_id)."}


@mcp.tool()
def create_group_change_request(
    group_id: Annotated[str, Field(pattern=r"^GRP-[0-9A-F]{10}$", description="A group_id from plan_change_groups.")],
    implementation_plan: Annotated[str, Field(description="Numbered steps; empty = Neo's canary-and-waves default.")] = "",
    backout_plan: Annotated[str, Field(description="Per-host rollback; empty = Neo's default for the cloud.")] = "",
    test_plan: Annotated[str, Field(description="Health check plus targeted re-scan; empty = default.")] = "",
    window_start: Annotated[str, Field(description="ISO-8601 start. Empty = tier default.")] = "",
    window_end: Annotated[str, Field(description="ISO-8601 end. Empty = sized to the number of hosts.")] = "",
    assignment_group: Annotated[str, Field(description="ServiceNow group to assign. Optional.")] = "",
    max_hosts: Annotated[int, Field(ge=1, le=500)] = _change_groups.MAX_HOSTS_PER_CHANGE,
) -> dict[str, Any]:
    """Raise ONE ServiceNow change for every host in a planned fix group, then wait for CAB.

    The change lists every host as an affected CI and nothing else. A production change states
    that it executes only after non-production is patched and soaked, citing the non-production
    change numbers. This approves and runs nothing; CAB approves in ServiceNow.
    """
    store = _store()
    try:
        g = _change_groups.find_group(store, group_id, max_hosts)
        start, end = _change_groups.default_group_window(g)
        if window_start:
            start = _utc(window_start)
            end = _utc(window_end) if window_end else start + timedelta(hours=4)
        req = _change_groups.build_group_request(
            g, start, end, implementation_plan, backout_plan, test_plan, assignment_group or None,
            _change_groups.nonprod_changes_for(store, g))
        items = _change_groups.submit_group_change(store, _snow(), g, req)
    except (ValueError, ChangeError) as e:
        return {"error": str(e)}
    return {"group_id": g.group_id, "change_number": items[0].refs["chg_number"], "type": req.type,
            "environment": g.environment, "hosts": g.hosts, "item_ids": [i.item_id for i in items],
            "window_start": start.isoformat(), "window_end": end.isoformat(),
            "next": "CAB must approve in ServiceNow; then call sync_change_approvals."}


@mcp.tool()
def execute_change(
    change_number: Annotated[str, Field(pattern=r"^CHG\d{7}$", description="An approved path-B change.")],
    dry_run: Annotated[bool, Field(description="True (default): only say what would happen. False patches.")] = True,
    wave_size: Annotated[int, Field(ge=1, le=50, description="Hosts per wave after the canary.")] = _patcher.DEFAULT_WAVE_SIZE,
    simulate_failure_at: Annotated[Optional[str], Field(description="Mock only: snapshot | apply | health | rollback.")] = None,
    simulate_failure_host: Annotated[Optional[str], Field(description="Mock only: fail just this host.")] = None,
) -> dict[str, Any]:
    """Patch every approved host on one change: a canary host first, then waves.

    Every host passes the same gates as execute_patch, plus production waits for non-production.
    The run halts at the first failed host; that host is rolled back and hosts not yet touched are
    released for a new change. Patched hosts are DEPLOYED, not remediated: a re-scan decides, and
    close_verified_changes closes the change once every host has an outcome. Dry-run first.
    """
    if not MOCK_MODE:
        return {"error": "no live patch backend is configured; execute_change only runs against the mock"}
    try:
        backend = _patcher.MockPatchBackend(simulate_failure_at, {simulate_failure_host} if simulate_failure_host else None)
        r = _patcher.run_change(_store(), _snow(), backend, change_number, wave_size, dry_run)
    except (ValueError, ChangeError) as e:
        return {"error": str(e)}
    return {"change_number": change_number,
            "waves": [[{"item_id": x.item_id, "outcome": x.outcome, "detail": x.detail} for x in w] for w in r.waves],
            "halted": r.halted, "released": r.released, "closed": r.closed}


SUGGESTION_KINDS = ("fix", "path", "controls", "triage", "other")
MAX_SUGGESTIONS = 20


@mcp.tool()
def record_agent_suggestion(
    item_id: Annotated[str, Field(description="Remediation item the advice is about.", pattern=_ITEM_ID_PATTERN)],
    text: Annotated[str, Field(min_length=1, max_length=2000, description=(
        "Your advice for the people who will act: what to do, why, and what to check first."))],
    kind: Annotated[str, Field(description="fix | path | controls | triage | other")] = "other",
) -> dict[str, Any]:
    """Record your recommendation on an item so the dashboard and reviewers can see it.

    Advisory only: this changes no state and approves nothing. Use it after triage or planning,
    for example "Path B is right: log4j-core 2.17.1 is the fixed version; patch i-0public-web-01
    in tonight's window, and check the app still starts". Keeps the latest 20 per item.
    """
    if kind not in SUGGESTION_KINDS:
        return {"error": f"kind must be one of {', '.join(SUGGESTION_KINDS)}"}
    store = _store()
    item = store.get(item_id)
    if item is None:
        return {"error": f"no such item: {item_id}"}
    now = datetime.now(timezone.utc).isoformat()
    item.suggestions = [*item.suggestions, {"at": now, "author": "neo-agent", "kind": kind, "text": text}][-MAX_SUGGESTIONS:]
    item.updated_at = now
    store.save(item, f"agent suggestion recorded ({kind})")
    return {"item_id": item_id, "suggestions": len(item.suggestions)}


@mcp.tool()
def execute_patch(
    item_id: Annotated[str, Field(description="Remediation item on path B in state APPROVED.", pattern=_ITEM_ID_PATTERN)],
    dry_run: Annotated[bool, Field(description=(
        "True (default): only check the gate and say what would happen. Set false to patch."))] = True,
    simulate_failure_at: Annotated[Optional[str], Field(description=(
        "Mock only: snapshot | apply | health | rollback."))] = None,
) -> dict[str, Any]:
    """Run the patch executor on one approved path-B item, inside its change window.

    Re-checks ServiceNow itself (change in Implement, approved, inside the window, host on the
    change's CI list), snapshots, patches, health-checks, and rolls back on failure. Success
    leaves the item DEPLOYED, NOT remediated: only a later re-scan closes it. Always do a dry
    run first and show the user. Today only a mock backend exists, so a live instance is refused.
    """
    if not MOCK_MODE:
        return {"error": "no live patch backend is configured; execute_patch only runs against the mock"}
    try:
        run = _patcher.run_patch(_store(), _snow(), _patcher.MockPatchBackend(simulate_failure_at),
                                 item_id, dry_run)
    except (ValueError, ChangeError) as e:
        return {"error": str(e)}
    return {"item_id": run.item_id, "outcome": run.outcome, "detail": run.detail, "steps": run.steps}


@mcp.tool()
def close_verified_changes() -> dict[str, Any]:
    """Close path-B ServiceNow changes on re-scan evidence, once every host on a change has an outcome.

    All patched hosts clean on re-scan -> successful; some clean, some still vulnerable, rolled
    back or not reached -> successful with issues; none -> unsuccessful. Each host's scan is cited.
    Run after track_remediation. Safe to repeat: each change is closed once.
    """
    try:
        r = _patcher.close_verified_changes(_store(), _snow())
    except ChangeError as e:
        return {"error": str(e)}
    return {"closed_successful": r.successful, "closed_with_issues": r.with_issues,
            "closed_unsuccessful": r.unsuccessful, "errors": r.errors}


@mcp.tool()
def mock_advance_change(
    change_number: Annotated[str, Field(description="Mock change number, e.g. CHG0030001.")],
    state: Annotated[ChangeState, Field(description="State to move the mock change to.")],
    approval: Annotated[Optional[str], Field(description="requested | approved | rejected")] = None,
    close_code: Annotated[Optional[str], Field(description=(
        "successful | unsuccessful: how the implementer closed the change (state CLOSED)."))] = None,
) -> dict[str, Any]:
    """Play the CAB and the change implementer against the MOCK ServiceNow so the flow can be demoed.

    Only usable when NEO_MOCK_MODE is true; refuses against a real instance.
    """
    if not MOCK_MODE:
        return {"error": "mock_advance_change is only available when NEO_MOCK_MODE=true"}
    if approval not in (None, "requested", "approved", "rejected"):
        return {"error": "approval must be requested, approved or rejected"}
    if close_code not in (None, "successful", "unsuccessful"):
        return {"error": "close_code must be successful or unsuccessful"}
    try:
        _snow().set_state(change_number, state, approval, close_code)
    except ChangeError as e:
        return {"error": str(e)}
    return {"change_number": change_number, "state": state.value, "approval": approval,
            "close_code": close_code}


# ---------------------------------------------------------------------------
# TOOLS — Path C: compensating controls for findings with no vendor patch
#
# The agent composes a proposal for the risk owner. It picks controls from the
# catalog (neo_core/controls.py); the weight is computed by code, never supplied
# by the agent. It cannot approve an exception, mark controls as applied, or
# write tags -- the human approves, and a change applies the tags.
# ---------------------------------------------------------------------------

def _scored_for(item: RemediationItem, scan_id: str) -> ScoredFinding | None:
    record = _SCORED_STORE.get(scan_id) if scan_id else None
    for d in (record or {}).get("scored_findings", []):
        sf = ScoredFinding.model_validate(d)
        if finding_key(sf.finding) == item.key:
            return sf
    return None


def _control_rows(ids: list[str]) -> list[dict[str, Any]]:
    return [{"id": c, "label": _controls.CATALOG[c].label, "weight": _controls.CATALOG[c].weight,
             "description": _controls.CATALOG[c].description} for c in ids]


def _control_proposal(item: RemediationItem, ids: list[str], sf: ScoredFinding | None) -> dict[str, Any]:
    unknown = [c for c in ids if c not in _controls.CATALOG]
    if unknown:
        raise ValueError(f"not in the control catalog: {', '.join(unknown)}")
    existing = _controls.current_tag(sf.context) if sf else None
    value, warnings = _controls.merge_tag(existing, ids)
    return {
        "item": _item_row(item),
        "controls": _control_rows(sorted(set(ids))),
        "combined_effect": _controls.effectiveness(ids),
        "score_impact": _controls.project(sf, ids) if sf else None,
        "tag": {
            "key": _controls.CONTROLS_TAG_KEY, "existing_value": existing, "new_value": value,
            "warnings": warnings,
            "command": _controls.tag_command(item.cloud_provider, item.resource_id, value),
            "note": "Informational. Neo does not write tags: apply through the change that "
                    "implements the controls. The next scan reads the tag and the exposure "
                    "factor drops by itself.",
        },
        "expiry_cap_days": _exceptions.MAX_EXCEPTION_DAYS.get(item.tier, 180),
    }


@mcp.tool()
def preview_control_impact(
    item_id: Annotated[str, Field(description="Path-C remediation item.", pattern=_ITEM_ID_PATTERN)],
    controls: Annotated[list[str], Field(description=(
        "Control IDs from the controls://catalog resource, e.g. ['virtual-patch', 'sg-restricted'].")),],
    scan_id: Annotated[str, Field(description="scan_id already passed to score_findings.")],
) -> dict[str, Any]:
    """What-if: the risk score and tier if these controls were in place. Changes nothing.

    Returns the combined effect, before/after score and tier, and the exact tag value and
    command that would make the exposure factor drop. Use it to find the smallest set of
    controls worth proposing. If the finding is KEV on a public asset the tier stays P1.
    """
    item = _store().get(item_id)
    if item is None:
        return {"error": f"no such item: {item_id}"}
    sf = _scored_for(item, scan_id)
    if sf is None:
        return {"error": "finding not in that scored scan", "hint": "Run score_findings(scan_id) first."}
    try:
        return _control_proposal(item, controls, sf)
    except ValueError as e:
        return {"error": str(e), "catalog": "controls://catalog"}


@mcp.tool()
def draft_risk_exception(
    item_id: Annotated[str, Field(description="Path-C remediation item.", pattern=_ITEM_ID_PATTERN)],
    controls: Annotated[list[str], Field(description="Control IDs from controls://catalog.", min_length=1)],
    justification: Annotated[str, Field(description=(
        "Why no patch is possible yet and why these controls are enough for now."))] = "",
    scan_id: Annotated[str, Field(description=(
        "scan_id already scored; include it so the proposal shows before/after numbers."))] = "",
) -> dict[str, Any]:
    """Submit a risk-exception draft for the risk owner and return the proposal to show them.

    Moves the item to IN_REVIEW. Does NOT approve it: a named risk owner approves with an
    expiry no longer than the tier cap, outside this agent. After approval, call
    create_controls_change_request: CAB approves that ServiceNow change and a person
    implements it manually. The controls only count when the change closes successfully;
    the next scan then reads the tag and lowers the exposure factor.
    """
    store = _store()
    item = store.get(item_id)
    if item is None:
        return {"error": f"no such item: {item_id}"}
    try:
        _exceptions.draft_exception(store, item_id, controls, justification)
        item = store.get(item_id)
        proposal = _control_proposal(item, controls, _scored_for(item, scan_id))
    except ValueError as e:
        return {"error": str(e), "catalog": "controls://catalog"}
    proposal["exception_id"] = item.exception.exception_id
    proposal["status"] = "awaiting risk-owner approval"
    proposal["approval"] = (f"neo remediate exception approve {item_id} --approver <NAME> --days <N>"
                            f"   (N at most {proposal['expiry_cap_days']} for {item.tier})")
    proposal["after_approval"] = [
        "agent: create_controls_change_request raises the ServiceNow change (steps + rollback written for you)",
        "CAB approves the change (emergency CAB for P1)",
        "a person implements the controls and the tag, then closes the change",
        "agent: sync_change_approvals records it; the next scan lowers the exposure factor",
    ]
    return proposal


@mcp.tool()
def create_controls_change_request(
    item_id: Annotated[str, Field(description="Path-C item whose exception the risk owner approved.",
                                  pattern=_ITEM_ID_PATTERN)],
    implementation_plan: Annotated[str, Field(description=(
        "Leave empty: Neo writes the steps from the approved controls and the tag to set."))] = "",
    backout_plan: Annotated[str, Field(description="Empty = default (record, undo in reverse, restore tag).")] = "",
    test_plan: Annotated[str, Field(description="Empty = default (each control active, tag set, next scan).")] = "",
    cis: Annotated[list[str], Field(description="CMDB CIs. Empty = just the item's host.")] = [],
    window_start: Annotated[str, Field(description="ISO-8601 (UTC if no offset). Empty = tier default.")] = "",
    window_end: Annotated[str, Field(description="ISO-8601. Empty = start + 4 hours.")] = "",
    assignment_group: Annotated[str, Field(description="ServiceNow group for the implementer. Optional.")] = "",
) -> dict[str, Any]:
    """Path C: raise the ServiceNow change that puts an APPROVED exception's controls in place.

    Refused until the risk owner has approved the exception. CAB then approves the change and
    a person implements it manually -- there is no executor. The controls only count once that
    change closes successfully (sync_change_approvals reports it). The window must end before
    the exception expires. P1 becomes an emergency change.
    """
    try:
        start = _utc(window_start) if window_start else None
        end = _utc(window_end) if window_end else None
        item = _exceptions.request_controls_change(
            _store(), _snow(), item_id, start, end, cis or None, implementation_plan,
            backout_plan, test_plan, assignment_group or None)
    except (ValueError, ChangeError) as e:
        return {"error": str(e)}
    exc = item.exception
    return {
        "item_id": item.item_id, "change_number": exc.change_ref, "controls": exc.controls,
        "tag_to_set": f"{_controls.CONTROLS_TAG_KEY}={exc.tag_value}", "exception_expires": exc.expires,
        "next": "CAB approves in ServiceNow, a person implements and closes the change, then "
                "call sync_change_approvals. Nothing is applied until then.",
    }


# ---------------------------------------------------------------------------
# RESOURCES — Remediation items
# ---------------------------------------------------------------------------

@mcp.resource("controls://catalog", mime_type="application/json",
              description="Compensating-control catalog: the only controls that earn credit, "
                          "with their weights. Weights combine as 1 - prod(1 - w), capped.")
def controls_catalog() -> str:
    return json.dumps({"max_effectiveness": _controls.MAX_EFFECTIVENESS,
                       "controls": _control_rows(list(_controls.CATALOG))})

@mcp.resource("remediation://items", mime_type="application/json",
              description="Every tracked remediation item: tier, path (A/B/C), state, "
                          "SLA due date, and linked change number.")
def remediation_items() -> str:
    return json.dumps([_item_row(i) for i in _store().list()], default=str)


@mcp.resource("remediation://item/{item_id}", mime_type="application/json",
              description="One remediation item in full: refs (PR / change / exception), "
                          "scan evidence, and its audit history.")
def remediation_item(item_id: str) -> str:
    item = _store().get(item_id)
    if item is None:
        return json.dumps({"item_id": item_id, "error": "not_found"})
    history = [{"at": at, "state": st, "event": ev} for at, st, ev in _store().history(item_id)]
    return json.dumps({**item.model_dump(mode="json"), "history": history}, default=str)


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
def draft_change_request(
    item_id:     Annotated[str, Field(description="Path-B remediation item, e.g. REM-75B178701B.")],
    cve_id:      Annotated[str, Field(description="CVE being patched.")],
    package_name: Annotated[str, Field(description="Vulnerable package.")],
    fixed_version: Annotated[str, Field(description="First safe version (may be empty).")],
    resource_id: Annotated[str, Field(description="Host being patched.")],
    cloud_provider: Annotated[str, Field(description="aws | azure | gcp | onprem.")] = "aws",
    tier:        Annotated[str, Field(description="Risk tier: P1 / P2 / P3 / P4.")] = "P3",
) -> str:
    """Guide the agent to draft the three plans for a ServiceNow change, then raise it."""
    return (
        f"Draft a ServiceNow change to patch {cve_id} ({package_name} -> "
        f"{fixed_version or 'vendor-fixed version'}) on {resource_id} ({cloud_provider}, {tier}). "
        f"Remediation item: {item_id}.\n\n"
        "Write three plans, specific to this host and package:\n"
        "1. implementation_plan -- numbered steps to apply the update through the platform's "
        "update manager, including any service restart.\n"
        "2. backout_plan -- numbered: take a snapshot/checkpoint BEFORE patching; undo the update "
        "(uninstall the KB, or yum/dnf history undo); restore the snapshot if the health check fails.\n"
        "3. test_plan -- the post-patch health check, and a targeted re-scan showing the CVE absent.\n\n"
        f"Then call create_change_request(item_id='{item_id}', ...) with those plans. "
        "A P1 becomes an emergency change automatically. Do not claim the change is approved: "
        "CAB decides in ServiceNow. Afterwards call sync_change_approvals, and use "
        "check_patch_gate before anything is patched."
    )


@mcp.prompt()
def compose_compensating_controls(
    item_id:       Annotated[str, Field(description="Path-C remediation item, e.g. REM-18859F70DE.")],
    cve_id:        Annotated[str, Field(description="CVE with no vendor patch yet.")],
    resource_id:   Annotated[str, Field(description="Affected asset.")],
    tier:          Annotated[str, Field(description="Current tier: P1 / P2 / P3 / P4.")],
    exposure:      Annotated[str, Field(description="public | internal | isolated | unknown.")],
    scan_id:       Annotated[str, Field(description="Scored scan this finding came from.")],
    target_tier:   Annotated[str, Field(description="Tier the owner wants to reach.")] = "P3",
) -> str:
    """Guide the agent to propose compensating controls to a risk owner for an unpatched CVE."""
    return (
        f"{cve_id} on {resource_id} ({tier}, {exposure}) has no vendor fix yet [{item_id}]. "
        f"Propose compensating controls so the owner can accept the risk for a limited time; "
        f"aim for {target_tier} or better.\n\n"
        "1. Read controls://catalog. Only those controls earn credit; their weights are fixed "
        "by policy and combine as independent layers (not added). Never invent a control or a weight.\n"
        "2. Choose controls that are realistic for THIS asset and exploit path (e.g. a WAF only "
        "helps a web-facing service). Prefer 'feature-disabled' or 'virtual-patch' when possible.\n"
        f"3. Call preview_control_impact(item_id='{item_id}', controls=[...], scan_id='{scan_id}') "
        "and try the smallest set that reaches the target. If it reports tier_pinned (actively "
        "exploited on a public asset), say plainly that the tier stays P1 and only the score drops.\n"
        "4. Present to the owner: the controls and why, the before/after score and tier, the exact "
        "tag and command that makes the exposure factor drop, and the expiry cap.\n"
        f"5. When the owner agrees, call draft_risk_exception(item_id='{item_id}', controls=[...], "
        f"justification=..., scan_id='{scan_id}').\n\n"
        "You cannot approve the exception, apply the controls or write the tag. Tell the owner the "
        "sequence: they approve; once they have, you raise a ServiceNow change "
        f"(create_controls_change_request(item_id='{item_id}')); CAB approves it; a PERSON "
        "implements the controls and sets the tag by hand and closes the change; only then do the "
        "controls count (sync_change_approvals), and the next scan lowers the exposure factor. "
        "The exception expires, so the controls must be in place before then; the finding reopens "
        "if it is still present afterwards."
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
