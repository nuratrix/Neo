"""Path B grouping: one change per fix, production and non-production apart, non-production first."""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from neo_core import change_groups as cg, patcher
from neo_core.closeout import sync_scan
from neo_core.models import AssetContext, Enrichment, Finding
from neo_core.remediation import State, environment_from_tags
from neo_core.remediation_store import SqliteStore
from neo_core.risk_engine import score_all
from neo_core.servicenow import ChangeState, MockChangeClient

T0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def _f(host, cve="CVE-1", pkg="openssl", ver="3.0.15", cloud="aws"):
    return Finding(cve_id=cve, resource_id=host, package_name=pkg, fixed_version=ver, cvss_base=9.0,
                   resource_type="AWS_EC2_INSTANCE", cloud_provider=cloud, finding_id=f"{host}-{cve}")


def _estate(spec, crit="high"):
    """spec: [(host, env, cve, pkg)] -> store with tracked path-B items."""
    s = SqliteStore(":memory:")
    fs = [_f(h, cve, pkg) for h, _, cve, pkg in spec]
    ctx = {h: AssetContext(resource_id=h, exposure="public", criticality=crit,
                           tags={"Environment": env} if env else {}) for h, env, _, _ in spec}
    enr = {f.cve_id: Enrichment(cve_id=f.cve_id, epss=0.9) for f in fs}
    sync_scan(s, score_all(fs, ctx, enr), "scan-1", T0)
    return s


def _approve(s, c, group, start=T0 + HOUR, hours=8):
    req = cg.build_group_request(group, start, start + hours * HOUR,
                                 nonprod_changes=cg.nonprod_changes_for(s, group))
    items = cg.submit_group_change(s, c, group, req, T0)
    num = items[0].refs["chg_number"]
    c.set_state(num, ChangeState.SCHEDULED, "approved")
    from neo_core.changes import sync_changes
    sync_changes(s, c, T0)
    c.set_state(num, ChangeState.IMPLEMENT)
    return num


def _rescan(s, hosts_still_vulnerable, spec, at):
    fs = [_f(h, cve, pkg) for h, _, cve, pkg in spec if h in hosts_still_vulnerable]
    ctx = {h: AssetContext(resource_id=h, exposure="public", criticality="high",
                           tags={"Environment": env} if env else {}) for h, env, _, _ in spec}
    sync_scan(s, score_all(fs, ctx, {"CVE-1": Enrichment(cve_id="CVE-1", epss=0.9)}), "rescan", at)


SPEC = [("web-1", "prod", "CVE-1", "openssl"), ("web-2", "prod", "CVE-1", "openssl"),
        ("web-3", "production", "CVE-1", "openssl"), ("dev-1", "dev", "CVE-1", "openssl"),
        ("qa-1", "QA", "CVE-1", "openssl"), ("web-1", "prod", "CVE-9", "curl")]


def test_environment_from_tags_treats_unknown_as_production():
    assert environment_from_tags({"Environment": "UAT"})[0] == "nonprod"
    assert environment_from_tags({"env": "Production"})[0] == "prod"
    assert environment_from_tags({"Environment": "blue"})[0] == "prod"
    assert environment_from_tags({})[0] == "prod"


def test_one_group_per_fix_and_environment_nonprod_first():
    s = _estate(SPEC)
    groups = cg.plan_groups(s)
    assert [(g.environment, g.package_name, len(g.hosts)) for g in groups] == [
        ("nonprod", "openssl", 2), ("prod", "curl", 1), ("prod", "openssl", 3)]
    prod = next(g for g in groups if g.environment == "prod" and g.package_name == "openssl")
    assert prod.hosts == ["web-1", "web-2", "web-3"]


def test_several_cves_fixed_by_one_package_share_one_ci():
    s = _estate([("web-1", "prod", "CVE-1", "openssl"), ("web-1", "prod", "CVE-2", "openssl")])
    [g] = cg.plan_groups(s)
    assert g.hosts == ["web-1"] and len(g.item_ids) == 2 and g.cve_ids == ["CVE-1", "CVE-2"]


def test_large_groups_are_split_by_max_hosts():
    s = _estate([(f"web-{i:02d}", "prod", "CVE-1", "openssl") for i in range(7)])
    groups = cg.plan_groups(s, max_hosts=3)
    assert [len(g.hosts) for g in groups] == [3, 3, 1]


def test_group_tier_is_the_highest_tier_and_sets_change_type():
    s = _estate([("web-1", "prod", "CVE-1", "openssl")], crit="critical")
    _estate_low = _estate([("web-2", "prod", "CVE-1", "openssl")], crit="low")
    # merge the low-criticality item into the same store
    for it in _estate_low.list():
        s.save(it)
    [g] = cg.plan_groups(s)
    tiers = sorted(i.tier for i in s.list())
    assert g.tier == tiers[0]
    req = cg.build_group_request(g, T0 + HOUR, T0 + 5 * HOUR)
    assert set(req.cis) == {"web-1", "web-2"} and "[GRP-" in req.short_description


def test_one_change_for_the_group_and_environments_never_mix():
    s, c = _estate(SPEC), MockChangeClient()
    nonprod = cg.plan_groups(s)[0]
    req = cg.build_group_request(nonprod, T0 + HOUR, T0 + 5 * HOUR)
    items = cg.submit_group_change(s, c, nonprod, req, T0)
    assert len({i.refs["chg_number"] for i in items}) == 1 and all(i.state is State.IN_REVIEW for i in items)
    assert len(c._data["changes"]) == 1 and set(c.affected_cis(items[0].refs["chg_number"])) == {"dev-1", "qa-1"}
    # forging a mixed group is refused
    prod = next(g for g in cg.plan_groups(s) if g.package_name == "openssl")
    bad = cg.ChangeGroup(**{**prod.__dict__, "item_ids": prod.item_ids + [items[0].item_id]})
    try:
        cg.submit_group_change(s, c, bad, cg.build_group_request(bad, T0 + HOUR, T0 + 5 * HOUR), T0)
        raise AssertionError("mixed group accepted")
    except ValueError:
        pass
    # the CI list must be exactly the group's hosts
    req2 = cg.build_group_request(prod, T0 + HOUR, T0 + 5 * HOUR).model_copy(update={"cis": ["web-1", "db-9"]})
    try:
        cg.submit_group_change(s, c, prod, req2, T0)
        raise AssertionError("foreign CI accepted")
    except ValueError:
        pass


def test_production_waits_for_nonproduction_and_its_soak():
    s, c = _estate(SPEC), MockChangeClient()
    groups = cg.plan_groups(s)
    nonprod = groups[0]
    prod = next(g for g in groups if g.environment == "prod" and g.package_name == "openssl")
    np_num = _approve(s, c, nonprod)
    p_num = _approve(s, c, prod)                         # CAB may approve both in parallel
    assert np_num in c._rec(p_num)["request"]["implementation_plan"]   # prod change cites the non-prod one

    run = patcher.run_change(s, c, patcher.MockPatchBackend(), p_num, now=T0 + 2 * HOUR)
    assert all(r.outcome == "refused" and "non-production" in r.detail for r in run.runs)
    assert not run.halted and all(s.get(i).state is State.APPROVED for i in prod.item_ids)

    assert [r.outcome for r in patcher.run_change(s, c, patcher.MockPatchBackend(), np_num,
                                                  now=T0 + 2 * HOUR).runs] == ["deployed", "deployed"]
    early = patcher.run_change(s, c, patcher.MockPatchBackend(), p_num, now=T0 + 3 * HOUR)
    assert all("soaking" in r.detail for r in early.runs)
    # P2/P3 soak is 24h; reopen the production window a day later
    c._rec(p_num)["end_date"] = (T0 + 40 * HOUR).isoformat()
    late = patcher.run_change(s, c, patcher.MockPatchBackend(), p_num, now=T0 + 2 * HOUR + 25 * HOUR)
    assert [r.outcome for r in late.runs] == ["deployed"] * 3


def test_failed_nonproduction_host_blocks_production():
    s, c = _estate(SPEC), MockChangeClient()
    nonprod = cg.plan_groups(s)[0]
    np_num = _approve(s, c, nonprod)
    patcher.run_change(s, c, patcher.MockPatchBackend("health", {"dev-1"}), np_num, now=T0 + 2 * HOUR)
    prod_item = next(i for i in s.list() if i.resource_id == "web-1" and i.package_name == "openssl")
    order = cg.precedence_gate(s, prod_item, T0 + 48 * HOUR)
    assert not order.allowed and "dev-1" in order.reason


def test_no_nonproduction_twin_needs_a_named_waiver():
    s = _estate([("web-1", "prod", "CVE-1", "openssl")])
    item = s.list()[0]
    assert not cg.precedence_gate(s, item, T0).allowed
    for approver, reason in (("", "a long enough reason for the waiver"), ("cm", "too short")):
        try:
            cg.waive_precedence(s, [item.item_id], approver, reason, T0)
            raise AssertionError("weak waiver accepted")
        except ValueError:
            pass
    cg.waive_precedence(s, [item.item_id], "change.manager", "single prod tier, no non-prod replica", T0)
    assert cg.precedence_gate(s, s.get(item.item_id), T0).allowed


def test_canary_failure_halts_releases_the_rest_and_closes_unsuccessful():
    hosts = [(f"dev-{i}", "dev", "CVE-1", "openssl") for i in range(4)]
    s, c = _estate(hosts), MockChangeClient()
    [g] = cg.plan_groups(s)
    num = _approve(s, c, g)
    b = patcher.MockPatchBackend("health", {"dev-0"})
    run = patcher.run_change(s, c, b, num, wave_size=2, now=T0 + 2 * HOUR)
    assert [r.outcome for r in run.runs] == ["rolled-back"] and run.halted.startswith("canary")
    assert {h for _, h in b.calls} == {"dev-0"} and len(run.released) == 3
    assert all(i.state is State.PROPOSED for i in s.list())
    assert c.get_change(num).state is ChangeState.CLOSED and c.get_change(num).close_code == "unsuccessful"


def test_wave_failure_keeps_earlier_hosts_and_closes_with_issues_after_rescan():
    spec = [(f"dev-{i}", "dev", "CVE-1", "openssl") for i in range(5)]
    s, c = _estate(spec), MockChangeClient()
    [g] = cg.plan_groups(s)
    num = _approve(s, c, g)
    run = patcher.run_change(s, c, patcher.MockPatchBackend("health", {"dev-2"}), num, wave_size=2,
                             now=T0 + 2 * HOUR)
    # canary dev-0, wave 1 = dev-1, dev-2 (dev-2 fails), wave 2 never runs
    assert [r.outcome for r in run.runs] == ["deployed", "deployed", "rolled-back"]
    assert len(run.released) == 2 and c.get_change(num).state is ChangeState.IMPLEMENT   # deployed hosts await re-scan
    _rescan(s, {"dev-2", "dev-3", "dev-4"}, spec, T0 + 6 * HOUR)
    r = patcher.close_verified_changes(s, c, T0 + 6 * HOUR)
    assert c.get_change(num).close_code == "successful_issues" and len(r.with_issues) == 2
    assert patcher.close_verified_changes(s, c, T0 + 7 * HOUR).with_issues == []          # once only


def test_all_hosts_fixed_closes_successful_and_shared_host_is_patched_once():
    spec = [("dev-1", "dev", "CVE-1", "openssl"), ("dev-1", "dev", "CVE-2", "openssl"),
            ("dev-2", "dev", "CVE-1", "openssl")]
    s, c = _estate(spec), MockChangeClient()
    [g] = cg.plan_groups(s)
    num = _approve(s, c, g)
    b = patcher.MockPatchBackend()
    patcher.run_change(s, c, b, num, now=T0 + 2 * HOUR)
    assert [x for x in b.calls if x[0] == "apply"] == [("apply", "dev-1"), ("apply", "dev-2")]
    assert all(i.state is State.DEPLOYED for i in s.list())
    _rescan(s, set(), spec, T0 + 6 * HOUR)
    r = patcher.close_verified_changes(s, c, T0 + 6 * HOUR)
    assert c.get_change(num).close_code == "successful" and len(r.successful) == 3


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
    print("all change-group tests passed")
