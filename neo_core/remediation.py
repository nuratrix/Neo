"""Remediation record and state machine.

One RemediationItem tracks one finding from "proposed fix" to "verified closed".
Delivery (PR, ServiceNow change, exception) happens elsewhere; this module only
owns what state an item is in and which moves are legal. A finding is closed by
scan evidence (see closeout.py), never by a job reporting success.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, Field

from .controls import current_tag
from .models import Finding, ScoredFinding


class Path(str, Enum):
    A = "A"   # code / image / IaC  -> GitHub PR
    B = "B"   # host OS or installed software with a fix -> ServiceNow change
    C = "C"   # no vendor fix yet -> time-limited risk exception


class State(str, Enum):
    PROPOSED = "PROPOSED"                  # agent drafted a fix, nothing submitted
    IN_REVIEW = "IN_REVIEW"                # PR open / change awaiting CAB
    APPROVED = "APPROVED"                  # human gate passed (merge / CAB / risk owner)
    DEPLOYED = "DEPLOYED"                  # fix rolled out; awaiting re-scan evidence
    EXCEPTION_ACTIVE = "EXCEPTION_ACTIVE"  # Path C: accepted risk until expiry
    REMEDIATED = "REMEDIATED"              # absent on a covering re-scan
    REOPENED = "REOPENED"                  # still present after the window, or regressed


TERMINAL = {State.REMEDIATED}

_S = State
TRANSITIONS: dict[State, set[State]] = {
    _S.PROPOSED:         {_S.IN_REVIEW, _S.REMEDIATED},
    # Path C: the risk owner's approval is IN_REVIEW -> EXCEPTION_ACTIVE; there is no way around it.
    _S.IN_REVIEW:        {_S.APPROVED, _S.EXCEPTION_ACTIVE, _S.PROPOSED, _S.REMEDIATED},
    # PROPOSED again = the patch run failed and was rolled back; it needs a new change.
    _S.APPROVED:         {_S.DEPLOYED, _S.REMEDIATED, _S.PROPOSED},
    _S.DEPLOYED:         {_S.REMEDIATED, _S.REOPENED},
    # PROPOSED again = vendor fix appeared, item re-routed to path A or B.
    _S.EXCEPTION_ACTIVE: {_S.PROPOSED, _S.REMEDIATED, _S.REOPENED},
    _S.REMEDIATED:       {_S.REOPENED},     # regression: finding came back
    _S.REOPENED:         {_S.IN_REVIEW, _S.REMEDIATED},
}

# Days from opening to remediation, by tier. Policy default -- tune per org.
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}

# Fix types that the router sends to Path A (everything else with a fix is B).
PATH_A_ECOSYSTEMS = {"maven", "pypi", "npm", "nuget", "golang", "cargo", "rubygems",
                     "composer", "iac", "terraform", "image"}
PATH_A_RESOURCE_TYPES = {"AWS_ECR_CONTAINER_IMAGE", "AWS_LAMBDA_FUNCTION", "CODE_REPOSITORY"}


class IllegalTransition(ValueError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def finding_key(f: Finding) -> str:
    """Stable identity across scans and scanners (finding_id is not stable everywhere)."""
    return f"{f.resource_id}|{f.cve_id}|{f.package_name}"


class ExceptionStatus(str, Enum):
    DRAFT = "DRAFT"              # drafted, awaiting the risk owner
    ACTIVE = "ACTIVE"            # approved, time-limited
    SUPERSEDED = "SUPERSEDED"    # vendor fix appeared; item re-routed to A or B
    REJECTED = "REJECTED"


class ExceptionRecord(BaseModel):
    """A time-limited, owned acceptance of risk while no vendor fix exists (path C)."""
    exception_id: str
    status: ExceptionStatus = ExceptionStatus.DRAFT
    controls: list[str]                  # catalog control IDs, e.g. "virtual-patch" (neo_core/controls.py)
    controls_effectiveness: float        # computed from the catalog, feeds AssetContext.compensating_controls
    tag_value: str = ""                  # what the asset's CompensatingControls tag should say
    justification: str = ""
    requested_at: str
    approved_by: str = ""                # named risk owner
    expires: str | None = None
    tag_warnings: list[str] = Field(default_factory=list)   # what merging into the existing tag discards
    controls_applied: bool = False       # true only once the ServiceNow change closed successfully
    change_ref: str = ""                 # the change that implements the controls (CHG number)
    change_status: str = ""              # that change's state at the last sync, e.g. AUTHORIZE
    tag_drift: list[str] = Field(default_factory=list)      # approved controls missing from the asset's tag at the last scan


class RemediationItem(BaseModel):
    item_id: str
    key: str
    finding_id: str = ""
    cve_id: str = ""
    resource_id: str = ""
    package_name: str = ""
    fixed_version: str = ""
    cloud_provider: str = ""
    controls_tag: str = ""               # CompensatingControls tag on the asset at the last scan
    # What the agent advised (advisory text only; it changes no state): {at, author, kind, text}.
    suggestions: list[dict[str, str]] = Field(default_factory=list)
    tier: str
    risk_score: float = 0.0
    path: Path
    state: State = State.PROPOSED
    created_at: str
    updated_at: str
    sla_due: str
    deployed_at: str | None = None
    remediated_at: str | None = None
    exception_expires: str | None = None
    sla_met: bool | None = None
    escalated: bool = False
    # Links back to the delivery system: pr_url, chg_number, exception_id.
    refs: dict[str, str] = Field(default_factory=dict)
    exception: ExceptionRecord | None = None
    # Scan evidence that justified each closure / reopen: {scan_id, at, result}.
    evidence: list[dict] = Field(default_factory=list)

    def move(self, new: State, now: datetime, **fields) -> None:
        """Apply a legal transition and the side effects that belong to it."""
        if new not in TRANSITIONS[self.state]:
            raise IllegalTransition(f"{self.item_id}: {self.state.value} -> {new.value}")
        self.state = new
        self.updated_at = now.isoformat()
        if new is State.DEPLOYED:
            self.deployed_at = now.isoformat()
        elif new is State.REMEDIATED:
            self.remediated_at = now.isoformat()
            self.sla_met = now <= datetime.fromisoformat(self.sla_due)
        elif new is State.REOPENED:
            self.remediated_at = None
            self.sla_met = None
        for k, v in fields.items():
            setattr(self, k, v)


def new_item(sf: ScoredFinding, path: Path, now: datetime | None = None) -> RemediationItem:
    now = now or utcnow()
    f = sf.finding
    key = finding_key(f)
    return RemediationItem(
        item_id="REM-" + _short_hash(key),
        key=key,
        finding_id=f.finding_id,
        cve_id=f.cve_id,
        resource_id=f.resource_id,
        package_name=f.package_name,
        fixed_version=f.fixed_version,
        cloud_provider=f.cloud_provider,
        controls_tag=current_tag(sf.context) or "",
        tier=sf.tier,
        risk_score=sf.risk_score,
        path=path,
        created_at=now.isoformat(),
        updated_at=now.isoformat(),
        sla_due=(now + timedelta(days=SLA_DAYS.get(sf.tier, SLA_DAYS["P4"]))).isoformat(),
    )


def _short_hash(s: str) -> str:
    import hashlib
    return hashlib.sha1(s.encode()).hexdigest()[:10].upper()
