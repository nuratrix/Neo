"""Path C: risk exceptions for findings the vendor has not patched yet.

The Neo agent drafts (judgment); everything here is deterministic code with the
human gates enforced by the state machine and by ServiceNow:

    draft_exception          PROPOSED/REOPENED -> IN_REVIEW    (agent)
    approve_exception        IN_REVIEW -> EXCEPTION_ACTIVE     (named risk owner, expiry <= tier max)
    reject_exception         IN_REVIEW -> PROPOSED
    request_controls_change  raise the ServiceNow change that implements the controls (after approval)
                             -> CAB approves -> a PERSON implements it; there is no executor
    sync_controls_changes    controls count as applied only when that change closes successfully
    overlay_contexts         feeds applied controls into the next scoring run (stands in for the tag)
    detect_tag_drift     approved controls missing from the scanned tag -> escalate, credit withdrawn
    watch_exceptions     vendor fix appears -> re-route to A or B
    expiring_soon        exceptions that need renewal

Expiry is enforced by closeout.apply_scan: expired and still present -> REOPENED + escalated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .changes import TIER_IMPACT, TIER_TYPE, default_window
from .controls import CATALOG, CONTROLS_TAG_KEY, effectiveness, merge_tag, parse_value, tag_command
from .models import AssetContext, ScoredFinding
from .remediation import (
    ExceptionRecord, ExceptionStatus, Path, RemediationItem, State, finding_key, utcnow,
)
from .remediation_store import RemediationStore
from .router import has_fix, route
from .servicenow import ChangeClient, ChangeError, ChangeRequest, ChangeState

# Longest an exception may run, by tier. Higher risk = shorter leash. Policy default -- tune per org.
MAX_EXCEPTION_DAYS = {"P1": 30, "P2": 60, "P3": 90, "P4": 180}


def _item(store: RemediationStore, item_id: str) -> RemediationItem:
    item = store.get(item_id)
    if item is None:
        raise ValueError(f"no such item: {item_id}")
    return item


def draft_exception(
    store: RemediationStore, item_id: str, controls: list[str],
    justification: str = "", now: datetime | None = None,
) -> RemediationItem:
    """`controls` are catalog IDs (controls.CATALOG). The weight is computed here, never supplied."""
    now = now or utcnow()
    item = _item(store, item_id)
    if item.path is not Path.C:
        raise ValueError(f"{item_id} is on path {item.path.value}; a fix exists, so no exception")
    if not controls:
        raise ValueError("an exception needs at least one compensating control")
    unknown = [c for c in controls if c not in CATALOG]
    if unknown:
        raise ValueError(f"not in the control catalog: {', '.join(unknown)} "
                         f"(a person adds a control to controls.CATALOG before it earns credit)")
    controls = sorted(set(controls))
    tag, warnings = merge_tag(item.controls_tag, controls)   # keep what is already tagged on the asset
    item.exception = ExceptionRecord(
        exception_id=f"EXC-{item.item_id[4:]}-{int(now.timestamp())}",
        controls=controls, controls_effectiveness=effectiveness(controls),
        tag_value=tag, tag_warnings=warnings,
        justification=justification, requested_at=now.isoformat(),
    )
    item.move(State.IN_REVIEW, now, refs={**item.refs, "exception_id": item.exception.exception_id})
    store.save(item, "exception drafted")
    return item


def approve_exception(
    store: RemediationStore, item_id: str, approver: str, expires: datetime,
    now: datetime | None = None,
) -> RemediationItem:
    now = now or utcnow()
    item = _item(store, item_id)
    exc = item.exception
    if item.state is not State.IN_REVIEW or exc is None or exc.status is not ExceptionStatus.DRAFT:
        raise ValueError(f"{item_id} has no exception awaiting approval")
    if not approver.strip():
        raise ValueError("an exception needs a named approver")
    if expires <= now:
        raise ValueError("expiry must be in the future")
    limit = timedelta(days=MAX_EXCEPTION_DAYS.get(item.tier, MAX_EXCEPTION_DAYS["P4"]))
    if expires - now > limit:
        raise ValueError(f"{item.tier} exceptions may run at most {limit.days} days")
    exc.status = ExceptionStatus.ACTIVE
    exc.approved_by = approver
    exc.expires = expires.isoformat()
    item.move(State.EXCEPTION_ACTIVE, now, exception_expires=expires.isoformat())
    store.save(item, f"exception approved by {approver}")
    return item


def reject_exception(
    store: RemediationStore, item_id: str, now: datetime | None = None,
) -> RemediationItem:
    now = now or utcnow()
    item = _item(store, item_id)
    if item.exception is None or item.state is not State.IN_REVIEW:
        raise ValueError(f"{item_id} has no exception awaiting approval")
    item.exception.status = ExceptionStatus.REJECTED
    item.move(State.PROPOSED, now)
    store.save(item, "exception rejected")
    return item


def controls_change_plans(item: RemediationItem) -> tuple[str, str, str]:
    """(implementation, backout, test) for the change that puts the approved controls in place."""
    exc = item.exception
    steps = [f"{i}. {CATALOG[c].label}: {CATALOG[c].description}" for i, c in enumerate(exc.controls, 1)]
    n = len(steps) + 1
    steps.append(f"{n}. Set the tag on {item.resource_id}: {CONTROLS_TAG_KEY}={exc.tag_value}   "
                 f"({tag_command(item.cloud_provider, item.resource_id, exc.tag_value)})")
    steps.append(f"{n + 1}. Record evidence that each control is active, then close the change.")
    previous = item.controls_tag or "(no tag)"
    backout = (f"1. Before changing anything, record the current rules, WAF/IPS rule-set version and tag "
               f"({previous}).\n"
               f"2. If a control misbehaves or the check below fails: remove the controls added by this "
               f"change in reverse order.\n"
               f"3. Restore the tag to {previous}.")
    test = (f"1. Confirm each control is active (e.g. the rule blocks a test request).\n"
            f"2. Confirm {CONTROLS_TAG_KEY} reads {exc.tag_value!r}.\n"
            f"3. Next scan: the exposure factor drops for {item.cve_id} on {item.resource_id}.")
    return "\n".join(steps), backout, test


def build_controls_request(
    item: RemediationItem, start: datetime, end: datetime, cis: list[str] | None = None,
    implementation: str = "", backout: str = "", test: str = "", assignment_group: str | None = None,
) -> ChangeRequest:
    exc = item.exception
    d_impl, d_back, d_test = controls_change_plans(item)
    return ChangeRequest(
        type=TIER_TYPE.get(item.tier, "normal"),
        short_description=f"Implement compensating controls for {item.cve_id} on {item.resource_id} "
                          f"({item.tier}) [{exc.exception_id}]",
        description=f"No vendor fix for {item.cve_id} yet. Risk accepted by {exc.approved_by} until "
                    f"{exc.expires[:10]} on condition that: {', '.join(exc.controls)}. "
                    f"Remediation item {item.item_id}.",
        justification=exc.justification or f"{item.tier} finding with no vendor patch; exception {exc.exception_id}.",
        implementation_plan=implementation or d_impl, backout_plan=backout or d_back,
        test_plan=test or d_test, cis=cis or [item.resource_id], impact=TIER_IMPACT.get(item.tier),
        assignment_group=assignment_group, start_date=start, end_date=end,
    )


def request_controls_change(
    store: RemediationStore, client: ChangeClient, item_id: str,
    start: datetime | None = None, end: datetime | None = None, cis: list[str] | None = None,
    implementation: str = "", backout: str = "", test: str = "", assignment_group: str | None = None,
    now: datetime | None = None,
) -> RemediationItem:
    """Raise the ServiceNow change that implements an APPROVED exception's controls.

    Only after the risk owner has approved. CAB approves the change and a person implements it;
    nothing counts as applied until sync_controls_changes sees that change close successfully.
    """
    now = now or utcnow()
    item = _item(store, item_id)
    exc = item.exception
    if item.state is not State.EXCEPTION_ACTIVE or exc is None or exc.status is not ExceptionStatus.ACTIVE:
        raise ValueError(f"{item_id} has no approved exception; the risk owner approves first")
    if exc.controls_applied:
        raise ValueError(f"{item_id}: controls already applied via {exc.change_ref}")
    if exc.change_ref:
        raise ValueError(f"{item_id}: change {exc.change_ref} is already in flight ({exc.change_status or 'new'})")
    if start is None:
        start, end = default_window(item, now)
    end = end or start + timedelta(hours=4)
    if cis and item.resource_id not in cis:
        raise ValueError(f"cis must include the item's own host {item.resource_id}")
    if end > datetime.fromisoformat(exc.expires):
        raise ValueError(f"the change window ends after the exception expires ({exc.expires[:10]}); "
                         f"the controls must be in place before then")
    req = build_controls_request(item, start, end, cis, implementation, backout, test, assignment_group)
    for name in ("implementation_plan", "backout_plan", "test_plan"):
        if not getattr(req, name).strip():
            raise ValueError(f"change needs a non-empty {name}")
    if end <= start or end <= now:
        raise ValueError("change window must end after it starts, in the future")
    rec = client.create_change(req)
    exc.change_ref, exc.change_status = rec.number, rec.state.value
    item.refs = {**item.refs, "chg_number": rec.number, "chg_sys_id": rec.sys_id}
    item.updated_at = now.isoformat()
    store.save(item, f"change {rec.number} raised ({req.type}) to implement {', '.join(exc.controls)}")
    return item


@dataclass
class ControlsSync:
    applied: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def sync_controls_changes(
    store: RemediationStore, client: ChangeClient, now: datetime | None = None,
) -> ControlsSync:
    """Read each controls change back from ServiceNow; only a successful close applies the controls."""
    now = now or utcnow()
    out = ControlsSync()
    for item in store.list(State.EXCEPTION_ACTIVE):
        exc = item.exception
        if exc is None or exc.status is not ExceptionStatus.ACTIVE or exc.controls_applied or not exc.change_ref:
            continue
        number = exc.change_ref
        try:
            rec = client.get_change(number)
        except ChangeError as e:
            out.errors[item.item_id] = str(e)
            continue
        event = ""
        if rec.state is ChangeState.CLOSED and rec.close_code == "successful":
            exc.controls_applied, exc.change_status = True, rec.state.value
            item.evidence.append({"scan_id": "", "at": now.isoformat(), "result": f"controls implemented, {number} closed successful"})
            event = f"controls applied: {number} closed successful"
            out.applied.append(item.item_id)
        elif rec.state is ChangeState.CLOSED or rec.state is ChangeState.CANCELED or rec.approval == "rejected":
            why = f"{number} {rec.state.value.lower()}" + (f" ({rec.close_code})" if rec.close_code else "")
            item.evidence.append({"scan_id": "", "at": now.isoformat(), "result": f"controls NOT implemented: {why}"})
            exc.change_ref, exc.change_status = "", ""          # free to raise a new change
            event = f"controls change failed: {why}"
            out.failed.append(item.item_id)
        elif exc.change_status != rec.state.value:
            exc.change_status = rec.state.value
            event = f"change {number} is {rec.state.value}"
        if event:
            item.updated_at = now.isoformat()
            store.save(item, event)
    return out


def overlay_contexts(
    store: RemediationStore, contexts: dict[str, AssetContext],
) -> dict[str, AssetContext]:
    """Raise compensating_controls for resources whose exception controls are applied.

    Stands in for the CompensatingControls tag the change writes to the real asset;
    use it when scoring from sources that do not read that tag yet.
    """
    out = dict(contexts)
    for item in store.list(State.EXCEPTION_ACTIVE):
        exc = item.exception
        if exc is None or not exc.controls_applied or exc.tag_drift:   # drifted: the tag is the truth
            continue
        ctx = out.get(item.resource_id) or AssetContext(resource_id=item.resource_id)
        if exc.controls_effectiveness > ctx.compensating_controls:
            out[item.resource_id] = ctx.model_copy(
                update={"compensating_controls": exc.controls_effectiveness})
    return out


@dataclass
class DriftResult:
    drifted: list[str] = field(default_factory=list)    # approved controls missing from the tag
    restored: list[str] = field(default_factory=list)   # drift cleared: the tag is back


def detect_tag_drift(
    store: RemediationStore, observed_tags: dict[str, str | None], now: datetime | None = None,
) -> DriftResult:
    """Compare the tag a scan saw with the controls the exception relies on.

    observed_tags maps resource_id -> raw CompensatingControls value (None = asset seen, no tag).
    A resource the scan did not see is skipped: no evidence either way. Drift escalates the item
    and takes the credit away on the next scoring run (see overlay_contexts); it does not end the
    exception, since a person must decide whether to re-apply the controls or accept the risk.
    """
    now = now or utcnow()
    out = DriftResult()
    for item in store.list(State.EXCEPTION_ACTIVE):
        exc = item.exception
        if exc is None or exc.status is not ExceptionStatus.ACTIVE or not exc.controls_applied:
            continue
        if item.resource_id not in observed_tags:
            continue
        have = set(parse_value(observed_tags[item.resource_id]).known)
        missing = [c for c in exc.controls if c not in have]
        if missing and missing != exc.tag_drift:
            exc.tag_drift = missing
            item.escalated = True
            item.evidence.append({"scan_id": "", "at": now.isoformat(),
                                  "result": f"tag drift: approved controls missing from the tag: {', '.join(missing)}"})
            item.updated_at = now.isoformat()
            store.save(item, f"tag drift: {', '.join(missing)} no longer on the asset")
            out.drifted.append(item.item_id)
        elif not missing and exc.tag_drift:
            exc.tag_drift = []
            item.evidence.append({"scan_id": "", "at": now.isoformat(), "result": "tag drift cleared: controls are back on the tag"})
            item.updated_at = now.isoformat()
            store.save(item, "tag drift cleared")
            out.restored.append(item.item_id)
    return out


def watch_exceptions(
    store: RemediationStore, scored: list[ScoredFinding], now: datetime | None = None,
) -> list[str]:
    """Re-route path C items whose finding now carries a fixed_version. Returns item IDs."""
    now = now or utcnow()
    by_key = {finding_key(sf.finding): sf.finding for sf in scored}
    rerouted = []
    for item in store.list():
        f = by_key.get(item.key)
        if item.path is not Path.C or item.state is State.REMEDIATED or f is None or not has_fix(f):
            continue
        fields = {"path": route(f), "fixed_version": f.fixed_version, "exception_expires": None}
        if item.exception and item.exception.status in (ExceptionStatus.DRAFT, ExceptionStatus.ACTIVE):
            item.exception.status = ExceptionStatus.SUPERSEDED
        if item.state in (State.IN_REVIEW, State.EXCEPTION_ACTIVE):
            item.move(State.PROPOSED, now, **fields)
        else:   # PROPOSED / REOPENED: nothing in flight to unwind
            for k, v in fields.items():
                setattr(item, k, v)
            item.updated_at = now.isoformat()
        store.save(item, f"vendor fix {f.fixed_version or '(version unknown)'} available; "
                         f"re-routed to path {item.path.value}")
        rerouted.append(item.item_id)
    return rerouted


def expiring_soon(
    store: RemediationStore, within: timedelta = timedelta(days=7), now: datetime | None = None,
) -> list[RemediationItem]:
    now = now or utcnow()
    return [
        i for i in store.list(State.EXCEPTION_ACTIVE)
        if i.exception_expires and datetime.fromisoformat(i.exception_expires) - now <= within
    ]
