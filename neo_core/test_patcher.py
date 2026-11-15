"""Path B patch executor: gate, rollback, DEPLOYED-not-REMEDIATED, close-on-evidence."""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from neo_core import changes, patcher
from neo_core.closeout import sync_scan
from neo_core.models import AssetContext, Enrichment, Finding
from neo_core.remediation import State
from neo_core.remediation_store import SqliteStore
from neo_core.risk_engine import score_all
from neo_core.servicenow import ChangeState, MockChangeClient

T0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
IN_WINDOW = T0 + 2 * HOUR


def _scored(f):
    return score_all([f], {f.resource_id: AssetContext(resource_id=f.resource_id, exposure="public",
                                                       criticality="critical")},
                     {f.cve_id: Enrichment(cve_id=f.cve_id, epss=0.9)})


def _finding(**kw):
    base = dict(cve_id="CVE-1", resource_id="i-1", package_name="openssl", cvss_base=9.0,
                resource_type="AWS_EC2_INSTANCE", fixed_version="2.0", cloud_provider="aws")
    return Finding(**{**base, **kw})


def _approved(**fkw):
    s, c = SqliteStore(":memory:"), MockChangeClient()
    f = _finding(**fkw)
    sync_scan(s, _scored(f), "scan-1", T0)
    item = s.list()[0]
    changes.submit_change(s, c, item.item_id,
                          changes.build_request(item, [item.resource_id], T0 + HOUR, T0 + 5 * HOUR), T0)
    num = s.get(item.item_id).refs["chg_number"]
    c.set_state(num, ChangeState.SCHEDULED, "approved")
    changes.sync_changes(s, c, T0)
    c.set_state(num, ChangeState.IMPLEMENT)
    return s, c, f, item.item_id, num


def test_happy_path_deploys_but_does_not_remediate_or_close_change():
    s, c, f, iid, num = _approved()
    b = patcher.MockPatchBackend()
    run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW)
    assert run.outcome == "deployed" and [x[0] for x in b.calls] == ["snapshot", "apply", "health"]
    item = s.get(iid)
    assert item.state is State.DEPLOYED and "patched_at" in item.refs
    assert c.get_change(num).state is ChangeState.IMPLEMENT              # not closed by "job success"
    assert any("[Neo patcher]" in n for n in c._rec(num)["notes"])
    assert patcher.run_patch(s, c, b, iid, now=IN_WINDOW).outcome == "refused"   # cannot run twice


def test_dry_run_touches_nothing():
    s, c, f, iid, num = _approved()
    b = patcher.MockPatchBackend()
    run = patcher.run_patch(s, c, b, iid, dry_run=True, now=IN_WINDOW)
    assert run.outcome == "dry-run" and b.calls == [] and s.get(iid).state is State.APPROVED


def test_gate_refusals_do_not_touch_the_host():
    s, c, f, iid, num = _approved()
    b = patcher.MockPatchBackend()
    assert "outside the change window" in patcher.run_patch(s, c, b, iid, now=T0).detail
    c.set_state(num, ChangeState.REVIEW)
    assert patcher.run_patch(s, c, b, iid, now=IN_WINDOW).outcome == "refused"
    assert b.calls == []


def test_unsafe_package_name_is_refused():
    s, c, f, iid, num = _approved(package_name="openssl; rm -rf /")
    b = patcher.MockPatchBackend()
    run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW)
    assert run.outcome == "refused" and b.calls == []


def test_snapshot_failure_leaves_host_untouched_and_item_approved():
    s, c, f, iid, num = _approved()
    b = patcher.MockPatchBackend("snapshot")
    run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW)
    assert run.outcome == "refused" and [x[0] for x in b.calls] == ["snapshot"]
    assert s.get(iid).state is State.APPROVED


def test_failed_apply_or_health_rolls_back_and_closes_change_unsuccessful():
    for point in ("apply", "health"):
        s, c, f, iid, num = _approved()
        b = patcher.MockPatchBackend(point)
        run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW)
        assert run.outcome == "rolled-back", point
        assert b.calls[-1][0] == "rollback"
        rec = c.get_change(num)
        assert rec.state is ChangeState.CLOSED and rec.close_code == "unsuccessful"
        item = s.get(iid)
        assert item.state is State.PROPOSED and "chg_number" not in item.refs   # needs a fresh change


def test_failed_rollback_blocks_the_item_for_a_person():
    s, c, f, iid, num = _approved()
    run = patcher.run_patch(s, c, patcher.MockPatchBackend("rollback"), iid, now=IN_WINDOW)
    item = s.get(iid)
    assert run.outcome == "needs-human" and item.escalated and "patch_blocked" in item.refs
    assert c.get_change(num).state is ChangeState.IMPLEMENT                 # left open
    again = patcher.MockPatchBackend()
    assert patcher.run_patch(s, c, again, iid, now=IN_WINDOW).outcome == "refused" and again.calls == []


def test_change_closes_successful_only_after_rescan_shows_it_gone():
    s, c, f, iid, num = _approved()
    patcher.run_patch(s, c, patcher.MockPatchBackend(), iid, now=IN_WINDOW)
    assert patcher.close_verified_changes(s, c, IN_WINDOW).successful == []        # still DEPLOYED
    sync_scan(s, [], "scan-2", IN_WINDOW + timedelta(hours=1))                      # CVE gone
    assert s.get(iid).state is State.REMEDIATED
    r = patcher.close_verified_changes(s, c, IN_WINDOW)
    assert r.successful == [iid]
    rec = c.get_change(num)
    assert rec.state is ChangeState.CLOSED and rec.close_code == "successful"
    assert "scan-2" in c._rec(num)["notes"][-1]
    assert patcher.close_verified_changes(s, c, IN_WINDOW).successful == []        # once only


def test_change_closes_unsuccessful_when_finding_persists():
    s, c, f, iid, num = _approved()
    patcher.run_patch(s, c, patcher.MockPatchBackend(), iid, now=IN_WINDOW)
    sync_scan(s, _scored(f), "scan-2", IN_WINDOW + timedelta(days=2))               # still there, past window
    assert s.get(iid).state is State.REOPENED
    r = patcher.close_verified_changes(s, c, IN_WINDOW)
    assert r.unsuccessful == [iid] and c.get_change(num).close_code == "unsuccessful"


def test_item_fixed_without_the_patcher_does_not_close_the_change():
    s, c, f, iid, num = _approved()
    sync_scan(s, [], "scan-2", IN_WINDOW)                                           # vanished, never patched
    assert patcher.close_verified_changes(s, c, IN_WINDOW).successful == []


class _SlowBackend(patcher.MockPatchBackend):
    """Hangs at one step for `delay` seconds."""
    def __init__(self, slow_at, delay=0.5):
        super().__init__()
        self.slow_at, self.delay = slow_at, delay

    def _call(self, step, host):
        super()._call(step, host)
        if step == self.slow_at:
            import time
            time.sleep(self.delay)


def test_snapshot_timeout_leaves_host_untouched():
    s, c, f, iid, num = _approved()
    b = _SlowBackend("snapshot")
    run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW, step_timeout=0.05)
    assert run.outcome == "refused" and "did not finish" in run.detail
    assert s.get(iid).state is State.APPROVED and [x[0] for x in b.calls] == ["snapshot"]


def test_apply_timeout_stops_for_a_person_and_does_not_roll_back_underneath_it():
    s, c, f, iid, num = _approved()
    b = _SlowBackend("apply")
    run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW, step_timeout=0.05)
    item = s.get(iid)
    assert run.outcome == "needs-human" and item.escalated and "host state unknown" in item.refs["patch_blocked"]
    assert "rollback" not in [x[0] for x in b.calls]
    assert c.get_change(num).state is ChangeState.IMPLEMENT


def test_health_check_timeout_rolls_back():
    s, c, f, iid, num = _approved()
    b = _SlowBackend("health")
    run = patcher.run_patch(s, c, b, iid, now=IN_WINDOW, step_timeout=0.05)
    assert run.outcome == "rolled-back" and b.calls[-1][0] == "rollback"


def _two_approved():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    fs = [_finding(resource_id="i-1", package_name="openssl"), _finding(resource_id="i-2", package_name="curl")]
    ctx = {f.resource_id: AssetContext(resource_id=f.resource_id, exposure="public", criticality="critical") for f in fs}
    sync_scan(s, score_all(fs, ctx, {"CVE-1": Enrichment(cve_id="CVE-1", epss=0.9)}), "scan-1", T0)
    ids = []
    for item in sorted(s.list(), key=lambda i: i.resource_id):
        changes.submit_change(s, c, item.item_id,
                              changes.build_request(item, [item.resource_id], T0 + HOUR, T0 + 5 * HOUR), T0)
        num = s.get(item.item_id).refs["chg_number"]
        c.set_state(num, ChangeState.SCHEDULED, "approved")
        changes.sync_changes(s, c, T0)
        c.set_state(num, ChangeState.IMPLEMENT)
        ids.append(item.item_id)
    return s, c, ids


def test_batch_patches_every_host_when_all_goes_well():
    s, c, ids = _two_approved()
    runs = patcher.run_patch_batch(s, c, patcher.MockPatchBackend(), ids, now=IN_WINDOW)
    assert [r.outcome for r in runs] == ["deployed", "deployed"]


def test_batch_halts_after_the_canary_fails_and_leaves_the_rest_untouched():
    s, c, ids = _two_approved()
    b = patcher.MockPatchBackend("health")
    runs = patcher.run_patch_batch(s, c, b, ids, now=IN_WINDOW)
    assert [r.outcome for r in runs] == ["rolled-back", "skipped"]
    assert {h for _, h in b.calls} == {"i-1"} and s.get(ids[1]).state is State.APPROVED


def test_batch_skips_a_refused_host_without_halting():
    s, c, ids = _two_approved()
    c.set_state(s.get(ids[0]).refs["chg_number"], ChangeState.REVIEW)       # first host's change not open
    runs = patcher.run_patch_batch(s, c, patcher.MockPatchBackend(), ids, now=IN_WINDOW)
    assert [r.outcome for r in runs] == ["refused", "deployed"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
    print("all patcher tests passed")
