"""Router, state machine and close-out rule tests (no AWS, network or ServiceNow)."""
import os
import sys
from datetime import datetime, timedelta, timezone

# Same import dance as test_securityhub.py: works with or without `pip install -e .`.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from neo_core import exceptions
    from neo_core.closeout import sync_scan
    from neo_core.models import AssetContext, Enrichment, Finding
    from neo_core.remediation import IllegalTransition, Path, State, finding_key
    from neo_core.remediation_store import SqliteStore
    from neo_core.risk_engine import score_all
    from neo_core.router import route
    from neo_core.servicenow import ChangeState, MockChangeClient
except ModuleNotFoundError:
    import exceptions
    from closeout import sync_scan
    from models import AssetContext, Enrichment, Finding
    from remediation import IllegalTransition, Path, State, finding_key
    from remediation_store import SqliteStore
    from risk_engine import score_all
    from router import route
    from servicenow import ChangeState, MockChangeClient

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _f(cve="CVE-1", resource="i-1", **kw) -> Finding:
    return Finding(cve_id=cve, resource_id=resource, package_name="pkg", cvss_base=9.0,
                   resource_type=kw.pop("resource_type", "AWS_EC2_INSTANCE"), **kw)


def _scored(*findings):
    ctx = {f.resource_id: AssetContext(resource_id=f.resource_id, exposure="public",
                                       criticality="critical") for f in findings}
    enr = {f.cve_id: Enrichment(cve_id=f.cve_id, epss=0.9) for f in findings}
    return score_all(list(findings), ctx, enr)


def _store():
    return SqliteStore(":memory:")


# --- router ---------------------------------------------------------------

def test_no_fixed_version_routes_to_c_even_for_a_dependency():
    assert route(_f(package_ecosystem="maven")) is Path.C


def test_dependency_image_and_iac_route_to_a():
    assert route(_f(fixed_version="2", package_ecosystem="maven")) is Path.A
    assert route(_f(fixed_version="2", resource_type="AWS_ECR_CONTAINER_IMAGE")) is Path.A
    assert route(_f(fixed_version="2", package_ecosystem="terraform")) is Path.A


def test_host_software_with_fix_routes_to_b():
    assert route(_f(fixed_version="2")) is Path.B


# --- state machine --------------------------------------------------------

def test_illegal_transition_rejected():
    s = _store()
    sync_scan(s, _scored(_f(fixed_version="2")), "scan-1", T0)
    item = s.list()[0]
    try:
        item.move(State.DEPLOYED, T0)   # skipped review and approval
    except IllegalTransition:
        return
    raise AssertionError("PROPOSED -> DEPLOYED must be illegal")


# --- close-out ------------------------------------------------------------

def _deploy(s, item, at):
    item.move(State.IN_REVIEW, at)
    item.move(State.APPROVED, at)
    item.move(State.DEPLOYED, at)
    s.save(item)


def test_absent_on_rescan_closes_and_records_sla():
    s = _store()
    sync_scan(s, _scored(_f(fixed_version="2")), "scan-1", T0)
    _deploy(s, s.list()[0], T0 + timedelta(hours=1))
    r = sync_scan(s, [], "scan-2", T0 + timedelta(days=1))
    item = s.list()[0]
    assert r.remediated == [item.item_id]
    assert item.state is State.REMEDIATED and item.sla_met is True
    assert item.evidence[-1]["scan_id"] == "scan-2"


def test_still_present_inside_window_is_left_alone_then_reopens_after():
    s = _store()
    sf = _scored(_f(fixed_version="2"))
    sync_scan(s, sf, "scan-1", T0)
    _deploy(s, s.list()[0], T0)
    sync_scan(s, sf, "scan-2", T0 + timedelta(hours=2))
    assert s.list()[0].state is State.DEPLOYED
    r = sync_scan(s, sf, "scan-3", T0 + timedelta(hours=30))
    item = s.list()[0]
    assert r.reopened == [item.item_id]
    assert item.state is State.REOPENED and item.escalated


def test_scan_that_did_not_cover_the_resource_cannot_close_it():
    s = _store()
    sync_scan(s, _scored(_f(fixed_version="2")), "scan-1", T0)
    r = sync_scan(s, [], "scan-2", T0 + timedelta(days=1), covered={"i-other"})
    assert r.remediated == [] and len(r.not_covered) == 1
    assert s.list()[0].state is State.PROPOSED


def test_regression_reopens_a_remediated_item():
    s = _store()
    sf = _scored(_f(fixed_version="2"))
    sync_scan(s, sf, "scan-1", T0)
    sync_scan(s, [], "scan-2", T0 + timedelta(days=1))
    assert s.list()[0].state is State.REMEDIATED
    sync_scan(s, sf, "scan-3", T0 + timedelta(days=2))
    assert s.list()[0].state is State.REOPENED


def test_expired_exception_reopens_and_escalates():
    s = _store()
    sf = _scored(_f())   # no fixed_version -> path C
    sync_scan(s, sf, "scan-1", T0)
    item = _active_exception(s, T0, days=30)
    assert item.path is Path.C
    sync_scan(s, sf, "scan-2", T0 + timedelta(days=10))
    assert s.list()[0].state is State.EXCEPTION_ACTIVE
    sync_scan(s, sf, "scan-3", T0 + timedelta(days=31))
    assert s.list()[0].state is State.REOPENED and s.list()[0].escalated


# --- path C ---------------------------------------------------------------

def _active_exception(s, at, days=30, controls=("feature-disabled",)):
    item = s.list()[0]
    exceptions.draft_exception(s, item.item_id, list(controls), "no patch yet", at)
    return exceptions.approve_exception(s, item.item_id, "risk.owner", at + timedelta(days=days), at)


def _raises(fn, exc=ValueError):
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"expected {exc.__name__}")


def test_exception_cannot_skip_the_approval_gate():
    s = _store()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    item = s.list()[0]
    _raises(lambda: item.move(State.EXCEPTION_ACTIVE, T0), IllegalTransition)
    _raises(lambda: exceptions.approve_exception(s, item.item_id, "owner", T0 + timedelta(days=5), T0))


def test_approval_needs_named_owner_and_respects_tier_cap():
    s = _store()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    item = s.list()[0]
    exceptions.draft_exception(s, item.item_id, ["waf-managed-rules"], "", T0)
    _raises(lambda: exceptions.approve_exception(s, item.item_id, " ", T0 + timedelta(days=5), T0))
    cap = exceptions.MAX_EXCEPTION_DAYS[item.tier]
    _raises(lambda: exceptions.approve_exception(s, item.item_id, "owner", T0 + timedelta(days=cap + 1), T0))
    _raises(lambda: exceptions.approve_exception(s, item.item_id, "owner", T0 - timedelta(days=1), T0))
    done = exceptions.approve_exception(s, item.item_id, "owner", T0 + timedelta(days=cap), T0)
    assert done.state is State.EXCEPTION_ACTIVE and done.exception.approved_by == "owner"


def test_exception_only_for_path_c():
    s = _store()
    sync_scan(s, _scored(_f(fixed_version="2")), "scan-1", T0)
    _raises(lambda: exceptions.draft_exception(s, s.list()[0].item_id, ["waf-managed-rules"], "", T0))


def _implement(s, client, at, code="successful"):
    """Raise the controls change, then play CAB and the person who implements and closes it."""
    item = exceptions.request_controls_change(s, client, s.list()[0].item_id, now=at)
    n = item.exception.change_ref
    client.set_state(n, ChangeState.IMPLEMENT, "approved")
    client.set_state(n, ChangeState.CLOSED, "approved", code)
    return exceptions.sync_controls_changes(s, client, at)


def test_controls_change_needs_an_approved_exception_first():
    s, c = _store(), MockChangeClient()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    item_id = s.list()[0].item_id
    _raises(lambda: exceptions.request_controls_change(s, c, item_id, now=T0))             # nothing drafted
    exceptions.draft_exception(s, item_id, ["virtual-patch"], "", T0)
    _raises(lambda: exceptions.request_controls_change(s, c, item_id, now=T0))             # drafted, not approved
    assert c._data["changes"] == {}


def test_controls_change_carries_steps_tag_rollback_and_emergency_type_for_p1():
    s, c = _store(), MockChangeClient()
    sync_scan(s, _scored(_f(cloud_provider="aws")), "scan-1", T0)
    _active_exception(s, T0, controls=("virtual-patch", "sg-restricted"))
    item = exceptions.request_controls_change(s, c, s.list()[0].item_id, now=T0)
    req = c._data["changes"][item.exception.change_ref]["request"]
    assert req["type"] == "emergency"                                                       # P1
    assert "Virtual patch" in req["implementation_plan"] and "Firewall / security group" in req["implementation_plan"]
    assert "CompensatingControls=sg-restricted_virtual-patch" in req["implementation_plan"]
    assert "aws ec2 create-tags" in req["implementation_plan"]
    assert "Restore the tag" in req["backout_plan"] and req["test_plan"]
    assert item.state is State.EXCEPTION_ACTIVE and not item.exception.controls_applied     # nothing applied yet


def test_controls_change_window_must_end_before_the_exception_expires():
    s, c = _store(), MockChangeClient()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    _active_exception(s, T0, days=10)
    item_id = s.list()[0].item_id
    _raises(lambda: exceptions.request_controls_change(
        s, c, item_id, T0 + timedelta(days=9), T0 + timedelta(days=11), now=T0))
    _raises(lambda: exceptions.request_controls_change(s, c, item_id, cis=["i-other"], now=T0))
    assert c._data["changes"] == {}


def test_only_one_controls_change_in_flight_and_none_after_applied():
    s, c = _store(), MockChangeClient()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    _active_exception(s, T0)
    item_id = s.list()[0].item_id
    exceptions.request_controls_change(s, c, item_id, now=T0)
    _raises(lambda: exceptions.request_controls_change(s, c, item_id, now=T0))             # already in flight
    n = s.list()[0].exception.change_ref
    c.set_state(n, ChangeState.CLOSED, "approved", "successful")
    exceptions.sync_controls_changes(s, c, T0)
    _raises(lambda: exceptions.request_controls_change(s, c, item_id, now=T0))             # already applied


def test_controls_count_only_after_the_change_closes_successfully():
    s, c = _store(), MockChangeClient()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    _active_exception(s, T0)
    item = exceptions.request_controls_change(s, c, s.list()[0].item_id, now=T0)
    n = item.exception.change_ref
    ctx = {"i-1": AssetContext(resource_id="i-1")}
    for state, approval in ((ChangeState.AUTHORIZE, "requested"), (ChangeState.SCHEDULED, "approved"),
                            (ChangeState.IMPLEMENT, "approved")):
        c.set_state(n, state, approval)
        r = exceptions.sync_controls_changes(s, c, T0)
        assert r.applied == [] and not s.list()[0].exception.controls_applied
        assert s.list()[0].exception.change_status == state.value
        assert exceptions.overlay_contexts(s, ctx)["i-1"].compensating_controls == 0.0     # no credit yet
    c.set_state(n, ChangeState.CLOSED, "approved", "successful")
    assert exceptions.sync_controls_changes(s, c, T0).applied == [item.item_id]
    done = s.list()[0]
    assert done.exception.controls_applied and "closed successful" in done.evidence[-1]["result"]
    assert exceptions.overlay_contexts(s, ctx)["i-1"].compensating_controls == done.exception.controls_effectiveness


def test_failed_or_cancelled_controls_change_gives_no_credit_and_frees_a_new_change():
    for how in ("unsuccessful", "canceled"):
        s, c = _store(), MockChangeClient()
        sync_scan(s, _scored(_f()), "scan-1", T0)
        _active_exception(s, T0)
        item = exceptions.request_controls_change(s, c, s.list()[0].item_id, now=T0)
        n = item.exception.change_ref
        if how == "canceled":
            c.set_state(n, ChangeState.CANCELED)
        else:
            c.set_state(n, ChangeState.CLOSED, "approved", "unsuccessful")
        assert exceptions.sync_controls_changes(s, c, T0).failed == [item.item_id], how
        after = s.list()[0]
        assert not after.exception.controls_applied and after.exception.change_ref == ""
        assert "NOT implemented" in after.evidence[-1]["result"]
        exceptions.request_controls_change(s, c, after.item_id, now=T0)                    # may try again


def test_draft_keeps_controls_already_tagged_on_the_asset():
    s = _store()
    f = _f()
    ctx = {"i-1": AssetContext(resource_id="i-1", exposure="public", criticality="critical",
                               tags={"CompensatingControls": "waf-managed-rules"},
                               compensating_controls=0.4)}
    sync_scan(s, score_all([f], ctx, {}), "scan-1", T0)
    item = s.list()[0]
    assert item.controls_tag == "waf-managed-rules"
    out = exceptions.draft_exception(s, item.item_id, ["virtual-patch"], "", T0)
    assert out.exception.tag_value == "virtual-patch_waf-managed-rules" and out.exception.tag_warnings == []


def test_applied_controls_lower_the_tier_on_next_sync():
    s = _store()
    f = _f()
    ctx = {f.resource_id: AssetContext(resource_id=f.resource_id, exposure="internal",
                                       criticality="high")}
    enr = {f.cve_id: Enrichment(cve_id=f.cve_id, epss=0.9)}
    before = score_all([f], ctx, enr)
    sync_scan(s, before, "scan-1", T0)
    _active_exception(s, T0, days=20)
    _implement(s, MockChangeClient(), T0)
    after = score_all([f], exceptions.overlay_contexts(s, ctx), enr)
    assert after[0].risk_score < before[0].risk_score
    r = sync_scan(s, after, "scan-2", T0 + timedelta(days=1))
    assert r.rescored == [s.list()[0].item_id]
    assert s.list()[0].risk_score == after[0].risk_score and s.list()[0].tier == after[0].tier


def _applied_item(s):
    f = _f()
    ctx = {f.resource_id: AssetContext(resource_id=f.resource_id, exposure="internal", criticality="high")}
    sync_scan(s, score_all([f], ctx, {}), "scan-1", T0)
    _active_exception(s, T0, days=20)
    _implement(s, MockChangeClient(), T0)
    return f, ctx, s.list()[0]


def test_tag_drift_flags_escalates_and_withdraws_credit_then_clears():
    s = _store()
    f, ctx, item = _applied_item(s)
    controls_ = item.exception.controls
    full = "_".join(controls_)
    rid = f.resource_id
    assert exceptions.detect_tag_drift(s, {rid: full}, T0).drifted == []            # tag matches
    assert exceptions.detect_tag_drift(s, {}, T0).drifted == []                     # not seen: no evidence

    r = exceptions.detect_tag_drift(s, {rid: None}, T0 + timedelta(days=1))          # tag removed
    drifted = s.get(item.item_id)
    assert r.drifted == [item.item_id] and drifted.escalated
    assert drifted.exception.tag_drift == controls_
    assert "tag drift" in drifted.evidence[-1]["result"]
    assert exceptions.overlay_contexts(s, ctx)[rid].compensating_controls == 0.0     # credit withdrawn
    assert exceptions.detect_tag_drift(s, {rid: None}, T0 + timedelta(days=2)).drifted == []   # no repeat noise

    r = exceptions.detect_tag_drift(s, {rid: full}, T0 + timedelta(days=3))          # tag back
    assert r.restored == [item.item_id] and s.get(item.item_id).exception.tag_drift == []
    assert exceptions.overlay_contexts(s, ctx)[rid].compensating_controls > 0


def test_partial_tag_is_drift_and_sync_scan_reports_it():
    s = _store()
    f, ctx, item = _applied_item(s)
    if len(item.exception.controls) < 2:
        item = s.get(item.item_id); item.exception.controls = ["virtual-patch", "sg-restricted"]; s.save(item, "test")
    keep = item.exception.controls[0]
    sf = score_all([f], ctx, {})
    r = sync_scan(s, sf, "scan-2", T0 + timedelta(days=1), observed_tags={f.resource_id: keep})
    assert r.drifted == [item.item_id]
    assert s.get(item.item_id).exception.tag_drift == item.exception.controls[1:]


def test_controls_not_yet_applied_do_not_change_scoring():
    s = _store()
    f = _f()
    ctx = {f.resource_id: AssetContext(resource_id=f.resource_id)}
    sync_scan(s, _scored(f), "scan-1", T0)
    _active_exception(s, T0)
    assert exceptions.overlay_contexts(s, ctx)[f.resource_id].compensating_controls == 0.0


def test_vendor_fix_reroutes_active_exception_to_a_or_b():
    s = _store()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    _active_exception(s, T0)
    fixed = _scored(_f(fixed_version="2.1", package_ecosystem="maven"))
    r = sync_scan(s, fixed, "scan-2", T0 + timedelta(days=3))
    item = s.list()[0]
    assert r.rerouted == [item.item_id]
    assert item.path is Path.A and item.state is State.PROPOSED
    assert item.fixed_version == "2.1" and item.exception_expires is None
    assert item.exception.status is exceptions.ExceptionStatus.SUPERSEDED


def test_expiring_soon_lists_only_exceptions_near_expiry():
    s = _store()
    sync_scan(s, _scored(_f()), "scan-1", T0)
    _active_exception(s, T0, days=20)
    assert exceptions.expiring_soon(s, timedelta(days=7), T0 + timedelta(days=5)) == []
    assert len(exceptions.expiring_soon(s, timedelta(days=7), T0 + timedelta(days=15))) == 1


def test_sync_is_idempotent_for_tracked_findings():
    s = _store()
    sf = _scored(_f(fixed_version="2"))
    assert len(sync_scan(s, sf, "scan-1", T0).opened) == 1
    assert sync_scan(s, sf, "scan-2", T0 + timedelta(hours=1)).opened == []
    assert len(s.list()) == 1 and s.list()[0].key == finding_key(sf[0].finding)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all remediation tests passed")
