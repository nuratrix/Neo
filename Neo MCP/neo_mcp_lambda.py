"""
Neo MCP Server — AWS Lambda Function URL handler
=================================================
Stateless, multi-tenant MCP server deployed on Lambda.

Each request must carry a valid Cognito IdToken in the Authorization header.
CognitoJWTMiddleware validates it and injects the Cognito sub claim as
customer_id via a contextvar, which all tools read to scope DynamoDB queries.

The scanning pipeline (neo_scan_trigger + neo_scan_executor) writes findings
into DynamoDB. This server is the AI read-query interface on top of that data:
Claude or any MCP-compatible agent calls these tools to triage, suppress, and
plan remediation for a customer's findings.

Env vars (set by Terraform):
  COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID
  NEO_FINDINGS_TABLE, NEO_CREDENTIALS_TABLE, NEO_SCANS_TABLE
  NEO_SCAN_QUEUE_URL
"""

from __future__ import annotations

import contextvars
import json
import os
import time
from datetime import datetime, timezone
from typing import Annotated, Any

import boto3
import httpx
from mangum import Mangum
from pydantic import Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp.server.fastmcp import FastMCP

# ── Contextvar for per-request customer isolation ─────────────────────────────
_CUSTOMER_ID: contextvars.ContextVar[str] = contextvars.ContextVar("customer_id", default="")

# ── Config ────────────────────────────────────────────────────────────────────
_REGION       = os.environ.get("AWS_REGION", "us-east-1")
_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
_CLIENT_ID    = os.environ.get("COGNITO_CLIENT_ID", "")
_JWKS_URL     = f"https://cognito-idp.{_REGION}.amazonaws.com/{_USER_POOL_ID}/.well-known/jwks.json"

NEO_CREDENTIALS_TABLE = os.environ.get("NEO_CREDENTIALS_TABLE", "")
NEO_FINDINGS_TABLE    = os.environ.get("NEO_FINDINGS_TABLE", "")
NEO_SCANS_TABLE       = os.environ.get("NEO_SCANS_TABLE", "")
NEO_SCAN_QUEUE_URL    = os.environ.get("NEO_SCAN_QUEUE_URL", "")

# Boto3 clients — reused across warm Lambda invocations
_dynamodb = boto3.resource("dynamodb", region_name=_REGION)
_sqs      = boto3.client("sqs", region_name=_REGION)

# ── JWKS validation ───────────────────────────────────────────────────────────
# PyJWKClient caches keys automatically; module-level instance reused on warm starts.
_jwks_client: Any = None  # lazy init to avoid cold-start import overhead

def _get_jwks_client():
    global _jwks_client
    if _jwks_client is None:
        import jwt as pyjwt
        _jwks_client = pyjwt.PyJWKClient(_JWKS_URL, cache_keys=True)
    return _jwks_client


def _validate_token(token: str) -> dict[str, Any]:
    """Validate Cognito JWT; return verified claims. Raises on failure."""
    import jwt as pyjwt
    client = _get_jwks_client()
    signing_key = client.get_signing_key_from_jwt(token)
    claims = pyjwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=_CLIENT_ID,
        options={"verify_exp": True},
    )
    if claims.get("token_use") not in ("id", "access"):
        raise ValueError(f"Unexpected token_use: {claims.get('token_use')}")
    return claims


# ── Cognito JWT middleware ─────────────────────────────────────────────────────
class _CognitoMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32001, "message": "Missing Bearer token"}}, status_code=401)

        try:
            claims = _validate_token(auth.removeprefix("Bearer ").strip())
        except Exception as exc:
            return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32001, "message": f"Unauthorized: {exc}"}}, status_code=401)

        cid = claims.get("sub", "")
        if not cid:
            return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32001, "message": "Token missing sub"}}, status_code=401)

        tok = _CUSTOMER_ID.set(cid)
        try:
            return await call_next(request)
        finally:
            _CUSTOMER_ID.reset(tok)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _customer() -> str:
    cid = _CUSTOMER_ID.get()
    if not cid:
        raise RuntimeError("No customer_id — request must pass through CognitoMiddleware")
    return cid

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# KEV cache (6-hour TTL, reused across warm starts)
_kev_cache: dict[str, Any] = {"data": None, "at": 0.0}
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss"

def _fetch_kev() -> dict[str, Any]:
    now = time.time()
    if _kev_cache["data"] and now - _kev_cache["at"] < 6 * 3600:
        return _kev_cache["data"]
    data = httpx.get(_KEV_URL, timeout=15).raise_for_status().json()
    _kev_cache.update(data=data, at=now)
    return data


# ── FastMCP instance ──────────────────────────────────────────────────────────
mcp = FastMCP("neo", stateless_http=True)


# ─────────────────────────────────────────────────────────────────────────────
# TOOLS — Findings
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_risk_summary() -> dict[str, Any]:
    """Return a P1/P2/P3/P4 tier breakdown and KEV count for the customer's open findings.

    Call this first to understand the current vulnerability posture before drilling in.
    """
    from boto3.dynamodb.conditions import Key, Attr
    cid = _customer()
    table = _dynamodb.Table(NEO_FINDINGS_TABLE)

    # Paginate through all open findings to build counts
    kw: dict[str, Any] = dict(
        KeyConditionExpression=Key("customer_id").eq(cid),
        FilterExpression=Attr("status").eq("OPEN"),
        ProjectionExpression="#t, kev, risk_score",
        ExpressionAttributeNames={"#t": "tier"},
    )
    counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    kev_count = 0
    total = 0
    while True:
        resp = table.query(**kw)
        for item in resp.get("Items", []):
            t = item.get("tier", "P4")
            counts[t] = counts.get(t, 0) + 1
            if item.get("kev"):
                kev_count += 1
            total += 1
        if "LastEvaluatedKey" not in resp:
            break
        kw["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    return {
        "total_open":     total,
        "tier_breakdown": counts,
        "kev_count":      kev_count,
        "risk_formula":   "risk = EPSS × (CVSS/10) × exposure_factor × 100",
        "tier_thresholds":"P1≥40 | P2≥20 | P3≥8 | P4<8 | KEV on public asset → always P1",
    }


@mcp.tool()
def list_findings(
    tier:           Annotated[str | None, Field(description="Filter: P1, P2, P3, or P4.")] = None,
    cloud_provider: Annotated[str | None, Field(description="Filter: aws, azure, gcp, nessus, qualys, rapid7.")] = None,
    kev_only:       Annotated[bool,       Field(description="Return only CISA KEV findings.")] = False,
    status:         Annotated[str,        Field(description="OPEN or SUPPRESSED.")] = "OPEN",
    limit:          Annotated[int,        Field(description="Maximum findings to return (1–200).", ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """List scored vulnerability findings for the authenticated customer with optional filters.

    Findings are sorted by risk_score descending (highest risk first).
    After calling this, use triage_finding prompt for any P1 you want to analyse deeply.
    """
    from boto3.dynamodb.conditions import Key, Attr
    cid = _customer()
    table = _dynamodb.Table(NEO_FINDINGS_TABLE)

    fe = Attr("status").eq(status)
    if tier:
        fe = fe & Attr("tier").eq(tier)
    if cloud_provider:
        fe = fe & Attr("cloud_provider").eq(cloud_provider)
    if kev_only:
        fe = fe & Attr("kev").eq(True)

    resp = table.query(
        KeyConditionExpression=Key("customer_id").eq(cid),
        FilterExpression=fe,
        Limit=limit,
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: float(x.get("risk_score", 0)), reverse=True)
    return {"count": len(items), "findings": items}


@mcp.tool()
def get_finding(
    finding_id: Annotated[str, Field(description="The finding_id to retrieve.")],
) -> dict[str, Any]:
    """Fetch a single vulnerability finding by ID, including full scoring breakdown."""
    cid = _customer()
    resp = _dynamodb.Table(NEO_FINDINGS_TABLE).get_item(
        Key={"customer_id": cid, "finding_id": finding_id}
    )
    item = resp.get("Item")
    return item if item else {"error": "not_found", "finding_id": finding_id}


@mcp.tool()
def suppress_finding(
    finding_id: Annotated[str, Field(description="Finding ID to suppress.")],
    reason:     Annotated[str, Field(description="Why this finding is being suppressed (audit trail).")] = "",
) -> dict[str, Any]:
    """Suppress a finding — moves it from OPEN to SUPPRESSED (non-destructive; can be reversed).

    Use when: risk accepted, compensating control confirmed, false positive identified.
    Always record a reason for the audit trail.
    """
    cid = _customer()
    _dynamodb.Table(NEO_FINDINGS_TABLE).update_item(
        Key={"customer_id": cid, "finding_id": finding_id},
        UpdateExpression="SET #s = :s, suppressed_at = :t, suppress_reason = :r",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "SUPPRESSED", ":t": _now_iso(), ":r": reason},
        ConditionExpression="attribute_exists(finding_id)",
    )
    return {"suppressed": True, "finding_id": finding_id, "reason": reason}


# ─────────────────────────────────────────────────────────────────────────────
# TOOLS — Sources & Scans
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_credentials() -> dict[str, Any]:
    """List registered vulnerability source credentials (cloud accounts + on-prem scanners).

    Sensitive fields (secrets, passwords, keys) are omitted from the response.
    """
    from boto3.dynamodb.conditions import Key
    cid = _customer()
    resp = _dynamodb.Table(NEO_CREDENTIALS_TABLE).query(
        KeyConditionExpression=Key("customer_id").eq(cid)
    )
    _STRIP = {"client_secret", "password", "secret_key", "access_key", "sa_key_json"}
    safe = [{k: v for k, v in item.items() if k not in _STRIP} for item in resp.get("Items", [])]
    return {"count": len(safe), "credentials": safe}


@mcp.tool()
def trigger_scan(
    credential_id: Annotated[str | None, Field(
        description="Credential ID to scan. Omit to queue a scan for all active sources."
    )] = None,
) -> dict[str, Any]:
    """Trigger an on-demand vulnerability scan for one or all registered sources.

    Scans run asynchronously; results appear in list_findings within a few minutes.
    """
    cid = _customer()
    msg: dict[str, Any] = {
        "customer_id":  cid,
        "triggered_by": "mcp",
        "triggered_at": _now_iso(),
    }
    if credential_id:
        msg["credential_id"] = credential_id

    _sqs.send_message(QueueUrl=NEO_SCAN_QUEUE_URL, MessageBody=json.dumps(msg))
    return {
        "queued":        True,
        "credential_id": credential_id,
        "message":       "Scan queued. Call list_findings in a few minutes to see updated results.",
    }


@mcp.tool()
def list_scans(
    limit: Annotated[int, Field(description="Max scan history entries (1–50).", ge=1, le=50)] = 20,
) -> dict[str, Any]:
    """List recent scan runs — useful to check if the most recent scan completed successfully."""
    from boto3.dynamodb.conditions import Key
    cid = _customer()
    resp = _dynamodb.Table(NEO_SCANS_TABLE).query(
        KeyConditionExpression=Key("customer_id").eq(cid),
        ScanIndexForward=False,
        Limit=limit,
    )
    return {"scans": resp.get("Items", [])}


# ─────────────────────────────────────────────────────────────────────────────
# RESOURCES — Threat intel (KEV + EPSS)
# ─────────────────────────────────────────────────────────────────────────────

@mcp.resource("kev://catalog", mime_type="application/json",
              description="Full CISA Known Exploited Vulnerabilities catalog (cached 6 h).")
def kev_catalog() -> str:
    return json.dumps(_fetch_kev())


@mcp.resource("kev://entry/{cve_id}", mime_type="application/json",
              description="Single KEV entry by CVE ID, or {in_kev: false} if not on the list.")
def kev_entry(cve_id: str) -> str:
    catalog = _fetch_kev()
    for entry in catalog.get("vulnerabilities", []):
        if entry.get("cveID", "").upper() == cve_id.upper():
            return json.dumps(entry)
    return json.dumps({"cve_id": cve_id, "in_kev": False})


@mcp.resource("epss://score/{cve_id}", mime_type="application/json",
              description="FIRST.org EPSS 30-day exploitation probability and percentile.")
def epss_score(cve_id: str) -> str:
    resp = httpx.get(_EPSS_URL, params={"cve": cve_id}, timeout=10).raise_for_status().json()
    rows = resp.get("data", [])
    if not rows:
        return json.dumps({"cve": cve_id, "epss": None, "percentile": None, "found": False})
    row = rows[0]
    return json.dumps({"cve": cve_id, "epss": float(row["epss"]), "percentile": float(row["percentile"])})


# ─────────────────────────────────────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

@mcp.prompt()
def triage_finding(
    cve_id:      Annotated[str,        Field(description="CVE identifier, e.g. CVE-2021-44228.")],
    title:       Annotated[str,        Field(description="Short vulnerability title.")],
    tier:        Annotated[str,        Field(description="Risk tier: P1 / P2 / P3 / P4.")],
    risk_score:  Annotated[float,      Field(description="Composite risk score 0–100.")],
    resource_id: Annotated[str,        Field(description="Affected resource.")],
    exposure:    Annotated[str,        Field(description="public | internal | isolated | unknown.")],
    cloud:       Annotated[str,        Field(description="aws | azure | gcp | onprem.")] = "aws",
    in_kev:      Annotated[bool,       Field(description="True if on the CISA KEV list.")] = False,
    epss:        Annotated[float | None, Field(description="EPSS probability (0–1).")] = None,
) -> str:
    """Triage a scored vulnerability finding and recommend an action."""
    kev_line  = "WARNING: This CVE is on the CISA KEV — actively exploited in the wild.\n" if in_kev else ""
    epss_line = f"EPSS 30-day exploitation probability: {epss:.1%}.\n" if epss is not None else ""
    return (
        f"Triage the following vulnerability and recommend an action.\n\n"
        f"CVE:      {cve_id}\n"
        f"Title:    {title}\n"
        f"Tier:     {tier}  (risk score {risk_score}/100)\n"
        f"Cloud:    {cloud}\n"
        f"Resource: {resource_id}  (exposure: {exposure})\n"
        f"{kev_line}{epss_line}\n"
        "Provide:\n"
        "1. A one-paragraph plain-language risk summary for a non-security engineer.\n"
        "2. Recommended action: patch immediately / schedule within SLA / accept risk / investigate.\n"
        "3. Suggested SLA (hours / days) justified by tier and exposure.\n"
        "4. Compensating controls that reduce real-world risk while the patch is pending."
    )


@mcp.prompt()
def remediation_plan(
    cve_id:        Annotated[str, Field(description="CVE identifier.")],
    title:         Annotated[str, Field(description="Short vulnerability title.")],
    package_name:  Annotated[str, Field(description="Vulnerable package, e.g. log4j-core.")],
    fixed_version: Annotated[str, Field(description="First safe version.")],
    resource_id:   Annotated[str, Field(description="Affected resource identifier.")],
    resource_type: Annotated[str, Field(description="e.g. AWS_EC2_INSTANCE.")],
    cloud:         Annotated[str, Field(description="aws | azure | gcp | onprem.")] = "aws",
) -> str:
    """Generate a step-by-step remediation plan for a vulnerability finding."""
    return (
        f"Generate a step-by-step remediation plan.\n\n"
        f"CVE:              {cve_id}\n"
        f"Title:            {title}\n"
        f"Vulnerable pkg:   {package_name}  →  fix in {fixed_version}\n"
        f"Cloud / platform: {cloud}\n"
        f"Affected resource:{resource_id}  ({resource_type})\n\n"
        "Include:\n"
        "1. Pre-remediation checklist: backup, rollback plan, test-env validation.\n"
        "2. Exact upgrade/patch commands for the affected OS or runtime.\n"
        "3. Validation steps to confirm the fix.\n"
        "4. Rollback steps if the patch causes a regression.\n"
        "5. A Terraform or Ansible snippet to codify the fix if applicable."
    )


@mcp.prompt()
def posture_briefing(
    total_open: Annotated[int,   Field(description="Total open findings.")],
    p1_count:   Annotated[int,   Field(description="P1 critical findings.")],
    p2_count:   Annotated[int,   Field(description="P2 high findings.")],
    p3_count:   Annotated[int,   Field(description="P3 medium findings.")],
    kev_count:  Annotated[int,   Field(description="Findings on the CISA KEV list.")],
    top_cves:   Annotated[str,   Field(description="Comma-separated top CVEs by risk score.")],
    period:     Annotated[str,   Field(description="Time period, e.g. 'last 7 days'.")] = "this week",
) -> str:
    """Generate an executive security posture briefing across all sources."""
    p4 = max(0, total_open - p1_count - p2_count - p3_count)
    return (
        f"Write an executive security posture briefing for {period}.\n\n"
        f"Open findings:  {total_open}  (P1={p1_count}, P2={p2_count}, P3={p3_count}, P4={p4})\n"
        f"KEV findings:   {kev_count}  (actively exploited CVEs)\n"
        f"Top CVEs:       {top_cves}\n\n"
        "Produce:\n"
        "1. A 3-sentence CISO-level summary of current risk posture.\n"
        "2. Priority action list: what must happen in 24 h / 7 d / 30 d.\n"
        "3. KEV callout — any KEV finding on a public asset is P1 regardless of score.\n"
        "4. Suggested ownership table: which team should own each P1 (infer from cloud provider and resource type)."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Lambda entry point
# ─────────────────────────────────────────────────────────────────────────────

def _build_app():
    asgi = mcp.streamable_http_app()
    asgi.add_middleware(_CognitoMiddleware)
    return asgi

_app = _build_app()
handler = Mangum(_app, lifespan="off")
