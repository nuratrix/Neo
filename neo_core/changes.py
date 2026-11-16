"""Path B: host patching through a ServiceNow change.

The Neo agent drafts the change content (judgment). Everything here is code:

    submit_change     PROPOSED/REOPENED -> IN_REVIEW   creates the change with its plans + CI list
    sync_changes      IN_REVIEW -> APPROVED            only when ServiceNow says CAB approved it
                      IN_REVIEW -> PROPOSED            change cancelled or rejected
    execution_gate    the check a patch executor must pass before touching anything

DEPLOYED is set by the patch executor after it runs, not here.

This module raises one change per item. For many hosts with the same fix, raise one change
per fix group instead (change_groups.py): production and non-production apart, non-production first.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .remediation import Path, RemediationItem, State, utcnow
from .remediation_store import RemediationStore
from .servicenow import ChangeClient, ChangeError, ChangeRequest, ChangeState

# Change type and impact come from the tier. P1 goes to the emergency CAB; the rest are normal
# changes. (Pre-approved standard changes for low-risk patch groups need a template -- later.)
TIER_TYPE = {"P1": "emergency", "P2": "normal", "P3": "normal", "P4": "normal"}
TIER_IMPACT = {"P1": "1", "P2": "2", "P3": "3", "P4": "3"}   # 1 High, 2 Medium, 3 Low

_SNAPSHOT = {
    "aws": "Create an EBS snapshot of every attached volume",
    "azure": "Create a VM restore point (managed-disk snapshots)",
    "gcp": "Create a persistent-disk snapshot",
}


def default_plans(item: RemediationItem) -> tuple[str, str, str]:
    """(implementation, backout, test) text used when the agent supplied none."""
    target = f" to {item.fixed_version}" if item.fixed_version else " to the vendor-fixed version"
    implementation = (
        f"1. Confirm the change state is Implement and the window is open.\n"
        f"2. Apply the {item.package_name or 'affected'} update{target} through the "
        f"platform's update manager on the approved CIs only.\n"
        f"3. Restart the affected service if the update requires it.")
    snap = _SNAPSHOT.get(item.cloud_provider, "Take a VM checkpoint / snapshot")
    backout = (
        f"1. {snap} before patching.\n"
        f"2. If the post-patch health check fails: uninstall the KB, or use yum/dnf history undo.\n"
        f"3. If that does not restore service: restore from the snapshot taken in step 1.")
    test = (f"Post-patch health check (service responds, no new errors), then a targeted re-scan "
            f"must show {item.cve_id} absent.")
    return implementation, backout, test


def build_request(
    item: RemediationItem, cis: list[str], start: datetime, end: datetime,
    implementation: str = "", backout: str = "", test: str = "",
    assignment_group: str | None = None,
) -> ChangeRequest:
    d_impl, d_back, d_test = default_plans(item)
    return ChangeRequest(
        type=TIER_TYPE.get(item.tier, "normal"),
        short_description=f"Patch {item.cve_id} on {item.resource_id} ({item.tier}) [{item.item_id}]",
        description=f"Neo remediation {item.item_id}: {item.cve_id} in {item.package_name or 'n/a'}, "
                    f"risk score {item.risk_score}, tier {item.tier}.",
        justification=f"{item.tier} vulnerability {item.cve_id}; SLA due {item.sla_due[:10]}.",
        implementation_plan=implementation or d_impl, backout_plan=backout or d_back,
        test_plan=test or d_test, cis=cis, impact=TIER_IMPACT.get(item.tier),
        assignment_group=assignment_group, start_date=start, end_date=end,
    )


def validate_request(req: ChangeRequest, now: datetime) -> None:
    """What every change must have before ServiceNow sees it. Raises ValueError."""
    for name in ("implementation_plan", "backout_plan", "test_plan"):
        if not getattr(req, name).strip():
            raise ValueError(f"change needs a non-empty {name}")
    if not req.cis:
        raise ValueError("change needs at least one CI")
    if req.end_date <= req.start_date:
        raise ValueError("change window must end after it starts")
    if req.end_date <= now:
        raise ValueError("change window is in the past")


STALE_RUN_REFS = ("patched_at", "snapshot", "patch_blocked", "rolled_back_under", "halted_under",
                  "chg_group", "chg_closed")   # left over from an earlier change or run


def _get(store: RemediationStore, item_id: str) -> RemediationItem:
    item = store.get(item_id)
    if item is None:
        raise ValueError(f"no such item: {item_id}")
    return item


def submit_change(
    store: RemediationStore, client: ChangeClient, item_id: str, req: ChangeRequest,
    now: datetime | None = None,
) -> RemediationItem:
    now = now or utcnow()
    item = _get(store, item_id)
    if item.path is not Path.B:
        raise ValueError(f"{item_id} is on path {item.path.value}, not B")
    if item.state not in (State.PROPOSED, State.REOPENED):
        raise ValueError(f"{item_id} is {item.state.value}; a change is only raised from PROPOSED or REOPENED")
    validate_request(req, now)
    rec = client.create_change(req)
    item.move(State.IN_REVIEW, now, refs={**{k: v for k, v in item.refs.items() if k not in STALE_RUN_REFS},
                                          "chg_number": rec.number, "chg_sys_id": rec.sys_id})
    store.save(item, f"change {rec.number} raised ({req.type}) for {len(req.cis)} CI(s)")
    return item


@dataclass
class ChangeSync:
    approved: list[str] = field(default_factory=list)
    declined: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def sync_changes(
    store: RemediationStore, client: ChangeClient, now: datetime | None = None,
) -> ChangeSync:
    """Pull CAB outcomes from ServiceNow into the items waiting on them."""
    now = now or utcnow()
    out = ChangeSync()
    seen: dict[str, object] = {}            # one ServiceNow read per change, however many items share it
    for item in store.list(State.IN_REVIEW):
        number = item.refs.get("chg_number")
        if item.path is not Path.B or not number:
            continue
        if number not in seen:
            try:
                seen[number] = client.get_change(number)
            except ChangeError as e:
                seen[number] = e
        rec = seen[number]
        if isinstance(rec, ChangeError):
            out.errors[item.item_id] = str(rec)
            continue
        if rec.state is ChangeState.CANCELED or rec.approval == "rejected":
            item.move(State.PROPOSED, now)
            store.save(item, f"change {number} cancelled or rejected")
            out.declined.append(item.item_id)
        elif rec.approval == "approved" and rec.state in (ChangeState.SCHEDULED, ChangeState.IMPLEMENT):
            item.move(State.APPROVED, now)
            store.save(item, f"change {number} approved")
            out.approved.append(item.item_id)
    return out


@dataclass
class Gate:
    allowed: bool
    reason: str
    instance_ids: list[str] = field(default_factory=list)   # the ONLY hosts the executor may touch


def execution_gate(
    client: ChangeClient, item: RemediationItem, now: datetime | None = None,
) -> Gate:
    """Re-check everything against ServiceNow at execution time; never trust cached state.

    Allowed only if: change state is Implement and approved, now is inside the change
    window, and this item's host is on the CI list read back from the change itself.
    The executor may touch the returned instance_ids and nothing else.
    """
    now = now or utcnow()
    number = item.refs.get("chg_number")
    if item.path is not Path.B or not number:
        return Gate(False, "item has no path-B change")
    if item.state is not State.APPROVED:
        return Gate(False, f"item is {item.state.value}, not APPROVED")
    try:
        rec = client.get_change(number)
        cis = client.affected_cis(number)
    except ChangeError as e:
        return Gate(False, f"cannot verify change: {e}")
    if rec.state is not ChangeState.IMPLEMENT:
        return Gate(False, f"{number} is {rec.state.value}, not IMPLEMENT")
    if rec.approval != "approved":
        return Gate(False, f"{number} approval is {rec.approval!r}")
    if not (rec.start_date and rec.end_date):
        return Gate(False, f"{number} has no change window")
    if not rec.start_date <= now <= rec.end_date:
        return Gate(False, f"outside the change window ({rec.start_date:%Y-%m-%d %H:%M} to "
                           f"{rec.end_date:%Y-%m-%d %H:%M} UTC)")
    if not cis:
        return Gate(False, f"{number} lists no CIs")
    if item.resource_id not in cis:
        return Gate(False, f"{item.resource_id} is not among the CIs approved on {number}")
    return Gate(True, "ok", [item.resource_id])


def default_window(item: RemediationItem, now: datetime | None = None) -> tuple[datetime, datetime]:
    """Emergency (P1) opens in an hour; everything else tomorrow. Four-hour window."""
    now = now or utcnow()
    start = now + (timedelta(hours=1) if TIER_TYPE.get(item.tier) == "emergency" else timedelta(days=1))
    return start, start + timedelta(hours=4)
