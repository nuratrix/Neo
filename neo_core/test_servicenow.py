"""Path B: ServiceNow client (mock + real over a fake transport), change flow, execution gate."""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from neo_core import changes
from neo_core.closeout import sync_scan
from neo_core.models import AssetContext, Enrichment, Finding
from neo_core.remediation import Path, State
from neo_core.remediation_store import SqliteStore
from neo_core.risk_engine import score_all
from neo_core.servicenow import (
    ChangeError, ChangeState, MockChangeClient, ServiceNowClient,
)

T0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def _item_in_store(store, resource="i-1", fixed="2.0", cloud="aws"):
    f = Finding(cve_id="CVE-1", resource_id=resource, package_name="openssl", cvss_base=9.0,
                resource_type="AWS_EC2_INSTANCE", fixed_version=fixed, cloud_provider=cloud)
    ctx = {resource: AssetContext(resource_id=resource, exposure="public", criticality="critical")}
    sync_scan(store, score_all([f], ctx, {"CVE-1": Enrichment(cve_id="CVE-1", epss=0.9)}), "scan-1", T0)
    item = store.list()[0]
    assert item.path is Path.B
    return item


def _req(item, cis=None, **kw):
    return changes.build_request(item, cis or [item.resource_id], T0 + HOUR, T0 + 5 * HOUR, **kw)


def _raises(fn, exc=ValueError):
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"expected {exc.__name__}")


# --- request building -----------------------------------------------------

def test_request_carries_plans_and_tier_driven_type_and_impact():
    item = _item_in_store(SqliteStore(":memory:"))
    req = _req(item)
    assert req.type == "emergency" and req.impact == "1"           # P1
    assert "EBS snapshot" in req.backout_plan                       # aws default rollback
    assert "yum/dnf history undo" in req.backout_plan
    assert item.item_id in req.short_description
    assert _req(item, backout="custom rollback").backout_plan == "custom rollback"


def test_azure_item_gets_azure_snapshot_wording():
    assert "restore point" in _req(_item_in_store(SqliteStore(":memory:"), cloud="azure")).backout_plan


# --- submit / sync --------------------------------------------------------

def test_submit_creates_change_and_moves_item_to_review():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item = _item_in_store(s)
    out = changes.submit_change(s, c, item.item_id, _req(item), T0)
    assert out.state is State.IN_REVIEW
    assert out.refs["chg_number"].startswith("CHG")
    assert c.affected_cis(out.refs["chg_number"]) == [item.resource_id]


def test_submit_refuses_missing_rollback_and_bad_windows():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item = _item_in_store(s)
    good = _req(item)
    _raises(lambda: changes.submit_change(s, c, item.item_id, good.model_copy(update={"backout_plan": " "}), T0))
    _raises(lambda: changes.submit_change(s, c, item.item_id, good.model_copy(update={"cis": []}), T0))
    _raises(lambda: changes.submit_change(
        s, c, item.item_id, good.model_copy(update={"end_date": good.start_date}), T0))
    _raises(lambda: changes.submit_change(s, c, item.item_id, good, T0 + timedelta(days=1)))   # window past
    assert c._data["changes"] == {}                       # nothing was created on any refusal


def test_sync_approves_only_after_cab():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item = _item_in_store(s)
    n = changes.submit_change(s, c, item.item_id, _req(item), T0).refs["chg_number"]
    assert changes.sync_changes(s, c, T0).approved == []                       # NEW, not approved
    c.set_state(n, ChangeState.AUTHORIZE, "requested")
    assert changes.sync_changes(s, c, T0).approved == []                       # waiting on CAB
    c.set_state(n, ChangeState.SCHEDULED, "approved")
    assert changes.sync_changes(s, c, T0).approved == [item.item_id]
    assert s.list()[0].state is State.APPROVED


def test_sync_sends_cancelled_change_back_to_proposed():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item = _item_in_store(s)
    n = changes.submit_change(s, c, item.item_id, _req(item), T0).refs["chg_number"]
    c.set_state(n, ChangeState.CANCELED)
    assert changes.sync_changes(s, c, T0).declined == [item.item_id]
    assert s.list()[0].state is State.PROPOSED


# --- execution gate -------------------------------------------------------

def _approved(s, c, state=ChangeState.IMPLEMENT, approval="approved"):
    item = _item_in_store(s)
    n = changes.submit_change(s, c, item.item_id, _req(item), T0).refs["chg_number"]
    c.set_state(n, ChangeState.SCHEDULED, "approved")
    changes.sync_changes(s, c, T0)
    c.set_state(n, state, approval)
    return s.list()[0], n


def test_gate_opens_only_in_implement_inside_window_for_listed_ci():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item, _ = _approved(s, c)
    g = changes.execution_gate(c, item, T0 + 2 * HOUR)
    assert g.allowed and g.instance_ids == [item.resource_id]


def test_gate_refuses_wrong_state_window_approval_and_unlisted_host():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item, n = _approved(s, c, state=ChangeState.SCHEDULED)
    assert "not IMPLEMENT" in changes.execution_gate(c, item, T0 + 2 * HOUR).reason
    c.set_state(n, ChangeState.IMPLEMENT, "approved")
    assert "outside the change window" in changes.execution_gate(c, item, T0 + timedelta(minutes=30)).reason
    assert "outside the change window" in changes.execution_gate(c, item, T0 + 6 * HOUR).reason
    c.set_state(n, ChangeState.IMPLEMENT, "requested")
    assert "approval" in changes.execution_gate(c, item, T0 + 2 * HOUR).reason
    c.set_state(n, ChangeState.IMPLEMENT, "approved")
    c._data["changes"][n]["cis"] = ["i-other"]
    assert "not among the CIs" in changes.execution_gate(c, item, T0 + 2 * HOUR).reason


def test_gate_refuses_item_that_is_not_approved_and_unknown_change():
    s, c = SqliteStore(":memory:"), MockChangeClient()
    item = _item_in_store(s)
    assert not changes.execution_gate(c, item, T0).allowed                     # no change at all
    item2 = changes.submit_change(s, c, item.item_id, _req(item), T0)
    assert "not APPROVED" in changes.execution_gate(c, item2, T0 + 2 * HOUR).reason
    item2.state = State.APPROVED
    item2.refs["chg_number"] = "CHG9999999"
    assert "cannot verify" in changes.execution_gate(c, item2, T0 + 2 * HOUR).reason


def test_close_change_records_outcome():
    c = MockChangeClient()
    item = _item_in_store(SqliteStore(":memory:"))
    n = c.create_change(_req(item)).number
    rec = c.close_change(n, successful=False, notes="health check failed; rolled back")
    assert rec.state is ChangeState.CLOSED and rec.close_code == "unsuccessful"


def test_mock_persists_between_runs():
    path = os.path.join(tempfile.mkdtemp(), "snow.json")
    item = _item_in_store(SqliteStore(":memory:"))
    n = MockChangeClient(path).create_change(_req(item)).number
    assert MockChangeClient(path).get_change(n).number == n
    assert MockChangeClient(path).create_change(_req(item)).number != n        # sequence continues


# --- real client over a fake transport -----------------------------------

def _fake_snow(calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path, q = request.url.path, dict(request.url.params)
        if request.method == "GET" and path.endswith("/cmdb_ci"):
            name = q["sysparm_query"].split("=", 1)[1]
            return httpx.Response(200, json={"result": [] if name == "ghost" else [{"sys_id": f"ci-{name}", "name": name}]})
        if request.method == "POST" and path.endswith("/change_request"):
            return httpx.Response(201, json={"result": {
                "number": "CHG0030009", "sys_id": "sys1", "state": "-5", "approval": "not requested",
                "type": "emergency", "start_date": "2026-01-01 13:00:00", "end_date": "2026-01-01 17:00:00"}})
        if request.method == "POST" and path.endswith("/task_ci"):
            return httpx.Response(201, json={"result": {"sys_id": "x"}})
        if request.method == "GET" and path.endswith("/change_request"):
            return httpx.Response(200, json={"result": [{
                "number": "CHG0030009", "sys_id": "sys1", "state": "-1", "approval": "approved",
                "type": "emergency", "start_date": "2026-01-01 13:00:00", "end_date": "2026-01-01 17:00:00"}]})
        if request.method == "GET" and path.endswith("/task_ci"):
            return httpx.Response(200, json={"result": [{"ci_item": {"display_value": "i-1", "value": "ci-i-1"}}]})
        if request.method == "PATCH":
            return httpx.Response(200, json={"result": {
                "number": "CHG0030009", "sys_id": "sys1", "state": "3", "approval": "approved",
                "type": "emergency", "close_code": json.loads(request.content).get("close_code", "")}})
        return httpx.Response(404, json={"error": "unexpected"})
    return handler


def _client(handler):
    http = httpx.Client(base_url="https://x.service-now.com", transport=httpx.MockTransport(handler))
    return ServiceNowClient("https://x.service-now.com", "u", "p", http=http)


def test_real_client_create_sends_plans_resolves_cis_and_links_them():
    calls = []
    item = _item_in_store(SqliteStore(":memory:"))
    rec = _client(_fake_snow(calls)).create_change(_req(item, cis=["i-1", "i-2"]))
    assert rec.number == "CHG0030009" and rec.state is ChangeState.NEW
    post = next(c for c in calls if c.method == "POST" and c.url.path.endswith("/change_request"))
    body = json.loads(post.content)
    assert body["backout_plan"] and body["implementation_plan"] and body["test_plan"]
    assert body["type"] == "emergency" and body["cmdb_ci"] == "ci-i-1"
    assert body["start_date"] == "2026-01-01 13:00:00"                         # UTC, ServiceNow format
    assert "risk" not in body                                                  # left to ServiceNow
    links = [json.loads(c.content) for c in calls if c.url.path.endswith("/task_ci") and c.method == "POST"]
    assert links == [{"task": "sys1", "ci_item": "ci-i-1"}, {"task": "sys1", "ci_item": "ci-i-2"}]


def test_real_client_refuses_unknown_ci_before_creating_anything():
    calls = []
    item = _item_in_store(SqliteStore(":memory:"))
    _raises(lambda: _client(_fake_snow(calls)).create_change(_req(item, cis=["i-1", "ghost"])), ChangeError)
    assert not any(c.method == "POST" for c in calls)


def test_real_client_reads_state_cis_and_closes():
    c = _client(_fake_snow([]))
    rec = c.get_change("CHG0030009")
    assert rec.state is ChangeState.IMPLEMENT and rec.approval == "approved"
    assert rec.start_date == datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
    assert c.affected_cis("CHG0030009") == ["i-1"]
    assert c.close_change("CHG0030009", True, "patched").close_code == "successful"


def test_real_client_surfaces_http_errors_and_unmapped_states():
    _raises(lambda: _client(lambda r: httpx.Response(403, text="ACL denied")).get_change("CHG1"), ChangeError)
    odd = lambda r: httpx.Response(200, json={"result": [{"number": "CHG1", "sys_id": "s", "state": "99"}]})
    _raises(lambda: _client(odd).get_change("CHG1"), ChangeError)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all servicenow tests passed")
