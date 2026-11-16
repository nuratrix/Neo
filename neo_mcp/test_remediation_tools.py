"""MCP tools for remediation tracking and path B (mock ServiceNow, no network).

Run: python neo_mcp/test_remediation_tools.py
"""
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["NEO_MOCK_MODE"] = "true"
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

import neo_mcp_server as srv
from neo_core.cli import _load_mock
from neo_core import change_groups
from neo_core.risk_engine import score_all

FIXTURE = os.path.join(ROOT, "neo_core", "examples", "mock_findings.json")
LOG4J = "REM-75B178701B"       # P1, host-patch -> path B
NGHTTP2 = "REM-18859F70DE"     # no fix -> path C


def _fresh(only: list[str] | None = None, scan_id="scan-1"):
    """New empty remediation DB + scored store (no EPSS/KEV network calls)."""
    srv.REMEDIATION_DB = os.path.join(tempfile.mkdtemp(), "rem.db")
    srv._remediation_store = None
    findings, contexts, enrichments = _load_mock(FIXTURE)
    scored = score_all(findings, contexts, enrichments)
    if only:
        scored = [s for s in scored if s.finding.cve_id in only]
    srv._SCORED_STORE[scan_id] = {"scored_findings": [s.model_dump() for s in scored]}
    return scan_id


def _open_window():
    return (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()


def test_tools_resources_and_prompt_are_registered_with_constraints():
    tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
    for name in ("track_remediation", "create_change_request", "sync_change_approvals",
                 "check_patch_gate", "mock_advance_change", "execute_patch", "close_verified_changes",
                 "record_agent_suggestion", "plan_change_groups", "create_group_change_request",
                 "execute_change"):
        assert name in tools, name
    # The agent gets no tool to approve a change or advance an item. It can patch, but only
    # through the executor's gate, and the tool defaults to a dry run.
    assert not {"approve_change", "advance_item", "waive_precedence"} & set(tools)
    assert tools["execute_change"].inputSchema["properties"]["dry_run"]["default"] is True
    assert tools["execute_patch"].inputSchema["properties"]["dry_run"]["default"] is True
    assert tools["create_change_request"].inputSchema["properties"]["item_id"]["pattern"].startswith("^REM-")
    assert any(p.name == "draft_change_request" for p in asyncio.run(srv.mcp.list_prompts()))
    uris = {str(r.uri) for r in asyncio.run(srv.mcp.list_resources())}
    assert "remediation://items" in uris


def test_track_opens_and_routes_items():
    sid = _fresh()
    r = srv.track_remediation(sid)
    assert len(r["opened"]) == 3
    rows = {i["item_id"]: i for i in json.loads(srv.remediation_items())}
    assert rows[LOG4J]["path"] == "B" and rows[LOG4J]["tier"] == "P1"
    assert rows[NGHTTP2]["path"] == "C"
    assert srv.track_remediation(sid)["opened"] == []             # idempotent


def test_track_unscored_scan_is_a_clear_error():
    _fresh()
    assert "not scored" in srv.track_remediation("nope")["error"]


def test_partial_scan_cannot_close_other_assets_findings():
    srv.track_remediation(_fresh())                                # all three tracked from a full scan
    srv._SCORED_STORE["scan-2"] = {"scored_findings": [            # next scan only reports nghttp2
        s for s in srv._SCORED_STORE["scan-1"]["scored_findings"]
        if s["finding"]["cve_id"] == "CVE-2023-44487"]}
    r = srv.track_remediation("scan-2")                            # not complete (default)
    assert r["remediated"] == [] and len(r["not_covered"]) == 2
    states = {i["item_id"]: i["state"] for i in json.loads(srv.remediation_items())}
    assert states[LOG4J] == "PROPOSED"
    r = srv.track_remediation("scan-2", scan_is_complete=True)     # caller asserts completeness
    assert LOG4J in r["remediated"]


def test_change_request_flow_end_to_end_in_mock():
    srv.track_remediation(_fresh())
    out = srv.create_change_request(LOG4J, window_start=_open_window())
    assert out["type"] == "emergency" and out["state"] == "IN_REVIEW"
    chg = out["change_number"]
    assert srv.check_patch_gate(LOG4J)["allowed"] is False           # not approved yet
    assert srv.sync_change_approvals()["approved"] == []             # CAB has not decided
    srv.mock_advance_change(chg, srv.ChangeState.SCHEDULED, "approved")
    assert srv.sync_change_approvals()["approved"] == [LOG4J]
    assert "not IMPLEMENT" in srv.check_patch_gate(LOG4J)["reason"]
    srv.mock_advance_change(chg, srv.ChangeState.IMPLEMENT, "approved")
    gate = srv.check_patch_gate(LOG4J)
    assert not gate["allowed"] and "non-production" in gate["precedence"]   # prod host, no non-prod twin
    change_groups.waive_precedence(srv._store(), [LOG4J], "change.manager",
                                   "single production web tier; no non-production replica exists")
    gate = srv.check_patch_gate(LOG4J)
    assert gate["allowed"] and gate["instance_ids"] == ["i-0public-web-01"]
    detail = json.loads(srv.remediation_item(LOG4J))
    assert detail["refs"]["chg_number"] == chg
    assert [h["state"] for h in detail["history"]][-3:-1] == ["IN_REVIEW", "APPROVED"]
    assert "waived" in detail["history"][-1]["event"]                       # the waiver is on the record


def test_execute_patch_dry_run_then_patch_then_close_on_rescan_evidence():
    srv.track_remediation(_fresh())
    chg = srv.create_change_request(LOG4J, window_start=_open_window())["change_number"]
    assert srv.execute_patch(LOG4J)["outcome"] == "refused"                     # not approved: gate says no
    srv.mock_advance_change(chg, srv.ChangeState.SCHEDULED, "approved")
    srv.sync_change_approvals()
    srv.mock_advance_change(chg, srv.ChangeState.IMPLEMENT, "approved")
    # A production host with no non-production twin: the executor refuses until a named person waives
    # the non-production-first rule. The agent has no tool for that; a person does it outside MCP.
    assert "non-production" in srv.execute_patch(LOG4J)["detail"]
    change_groups.waive_precedence(srv._store(), [LOG4J], "change.manager",
                                   "single production web tier; no non-production replica exists")
    assert srv.execute_patch(LOG4J)["outcome"] == "dry-run"                     # default touches nothing
    assert json.loads(srv.remediation_item(LOG4J))["state"] == "APPROVED"
    assert srv.execute_patch(LOG4J, dry_run=False)["outcome"] == "deployed"
    assert json.loads(srv.remediation_item(LOG4J))["state"] == "DEPLOYED"       # not REMEDIATED
    assert srv.close_verified_changes()["closed_successful"] == []              # no scan evidence yet


def test_agent_suggestion_is_recorded_without_changing_state():
    srv.track_remediation(_fresh())
    before = json.loads(srv.remediation_item(LOG4J))
    out = srv.record_agent_suggestion(LOG4J, "Path B is right: patch in tonight's window.", "path")
    assert out["suggestions"] == 1
    after = json.loads(srv.remediation_item(LOG4J))
    assert after["state"] == before["state"] and after["suggestions"][0]["kind"] == "path"
    assert "kind must be" in srv.record_agent_suggestion(LOG4J, "x", "approve")["error"]
    assert "no such item" in srv.record_agent_suggestion("REM-0000000000", "x")["error"]
    for i in range(25):
        srv.record_agent_suggestion(LOG4J, f"note {i}")
    assert len(json.loads(srv.remediation_item(LOG4J))["suggestions"]) == srv.MAX_SUGGESTIONS


def test_execute_patch_refuses_outside_mock_mode():
    old, srv.MOCK_MODE = srv.MOCK_MODE, False
    try:
        assert "no live patch backend" in srv.execute_patch(LOG4J, dry_run=False)["error"]
    finally:
        srv.MOCK_MODE = old


def test_change_request_refusals_return_errors_not_exceptions():
    srv.track_remediation(_fresh())
    assert "no such item" in srv.create_change_request("REM-0000000000")["error"]
    assert "path C" in srv.create_change_request(NGHTTP2)["error"] or "not B" in srv.create_change_request(NGHTTP2)["error"]
    assert "must include" in srv.create_change_request(LOG4J, cis=["i-other"])["error"]
    assert "past" in srv.create_change_request(
        LOG4J, window_start="2020-01-01T00:00:00+00:00")["error"]
    assert srv.create_change_request(LOG4J, window_start=_open_window())["state"] == "IN_REVIEW"
    assert "only raised from PROPOSED" in srv.create_change_request(LOG4J)["error"]   # no duplicate change


def test_mock_advance_refuses_outside_mock_mode():
    srv.track_remediation(_fresh())
    chg = srv.create_change_request(LOG4J, window_start=_open_window())["change_number"]
    srv.MOCK_MODE = False
    try:
        assert "NEO_MOCK_MODE" in srv.mock_advance_change(chg, srv.ChangeState.IMPLEMENT, "approved")["error"]
    finally:
        srv.MOCK_MODE = True
    assert "approval must be" in srv.mock_advance_change(chg, srv.ChangeState.IMPLEMENT, "yes")["error"]


# --- path C: compensating controls --------------------------------------------

def test_path_c_tools_registered_and_agent_cannot_approve_or_tag():
    names = {t.name for t in asyncio.run(srv.mcp.list_tools())}
    assert {"preview_control_impact", "draft_risk_exception"} <= names
    assert not {"approve_exception", "mark_controls_applied", "apply_tag", "set_tags"} & names
    props = {t.name: t.inputSchema["properties"] for t in asyncio.run(srv.mcp.list_tools())}
    assert "effectiveness" not in props["draft_risk_exception"]          # weight is never agent-supplied
    assert "controls://catalog" in {str(r.uri) for r in asyncio.run(srv.mcp.list_resources())}
    assert any(p.name == "compose_compensating_controls" for p in asyncio.run(srv.mcp.list_prompts()))
    cat = json.loads(srv.controls_catalog())
    assert {c["id"] for c in cat["controls"]} >= {"virtual-patch", "waf-managed-rules", "sg-restricted"}


def test_preview_shows_score_drop_tag_and_command_without_changing_anything():
    sid = _fresh()
    srv.track_remediation(sid)
    out = srv.preview_control_impact(NGHTTP2, ["virtual-patch", "waf-managed-rules"], sid)
    assert out["score_impact"]["after"]["risk_score"] < out["score_impact"]["before"]["risk_score"]
    assert out["tag"]["new_value"] == "virtual-patch_waf-managed-rules"
    assert "aws ec2 create-tags --resources i-0internal-api-01" in out["tag"]["command"]
    assert any("unverified" in w for w in out["tag"]["warnings"])        # fixture tag is a legacy "0.3"
    assert out["expiry_cap_days"] == 180                                 # P4
    assert json.loads(srv.remediation_item(NGHTTP2))["state"] == "PROPOSED"      # read-only


def test_preview_rejects_uncatalogued_controls_and_unscored_scans():
    sid = _fresh()
    srv.track_remediation(sid)
    bad = srv.preview_control_impact(NGHTTP2, ["home-made-firewall"], sid)
    assert "not in the control catalog" in bad["error"] and bad["catalog"] == "controls://catalog"
    assert "not in that scored scan" in srv.preview_control_impact(NGHTTP2, ["virtual-patch"], "nope")["error"]


def test_draft_moves_item_to_review_and_hands_the_human_an_approval_step():
    sid = _fresh()
    srv.track_remediation(sid)
    out = srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "no patch from vendor yet", sid)
    assert out["status"] == "awaiting risk-owner approval" and out["exception_id"].startswith("EXC-")
    assert "exception approve REM-18859F70DE" in out["approval"] and "at most 180" in out["approval"]
    detail = json.loads(srv.remediation_item(NGHTTP2))
    assert detail["state"] == "IN_REVIEW"
    assert detail["exception"]["controls"] == ["virtual-patch"]
    assert detail["exception"]["controls_effectiveness"] == 0.8          # computed from the catalog
    assert detail["exception"]["status"] == "DRAFT"                      # the agent cannot activate it


def test_draft_refuses_patchable_items_unknown_controls_and_duplicates():
    sid = _fresh()
    srv.track_remediation(sid)
    assert "path B" in srv.draft_risk_exception(LOG4J, ["virtual-patch"], "", sid)["error"]
    assert "not in the control catalog" in srv.draft_risk_exception(NGHTTP2, ["magic"], "", sid)["error"]
    assert srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "", sid)["status"]
    assert "error" in srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "", sid)    # already in review


def _approve(item_id, days=30):
    """The risk owner's step. Deliberately not available to the agent as a tool."""
    from neo_core import exceptions
    exceptions.approve_exception(srv._store(), item_id, "risk.owner",
                                 datetime.now(timezone.utc) + timedelta(days=days))


def test_controls_change_tool_is_refused_until_the_risk_owner_approves():
    sid = _fresh()
    srv.track_remediation(sid)
    assert "create_controls_change_request" in {t.name for t in asyncio.run(srv.mcp.list_tools())}
    assert "no approved exception" in srv.create_controls_change_request(NGHTTP2)["error"]    # nothing drafted
    srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "", sid)
    assert "no approved exception" in srv.create_controls_change_request(NGHTTP2)["error"]    # drafted only
    assert "error" in srv.create_controls_change_request(LOG4J)                               # path B item
    assert json.loads(srv.remediation_item(NGHTTP2))["exception"]["change_ref"] == ""


def test_controls_flow_agent_raises_change_person_implements_then_it_counts():
    sid = _fresh()
    srv.track_remediation(sid)
    srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "no vendor patch", sid)
    _approve(NGHTTP2)
    out = srv.create_controls_change_request(NGHTTP2)
    chg = out["change_number"]
    assert out["tag_to_set"] == "CompensatingControls=virtual-patch" and "Nothing is applied" in out["next"]
    assert "error" in srv.create_controls_change_request(NGHTTP2)                             # one in flight
    for state, approval in (("AUTHORIZE", "requested"), ("IMPLEMENT", "approved")):
        srv.mock_advance_change(chg, srv.ChangeState(state), approval)
        r = srv.sync_change_approvals()
        assert r["controls_applied"] == [] and r["controls_change_failed"] == []
    exc = json.loads(srv.remediation_item(NGHTTP2))["exception"]
    assert exc["controls_applied"] is False and exc["change_status"] == "IMPLEMENT"
    srv.mock_advance_change(chg, srv.ChangeState.CLOSED, "approved", "successful")             # the person closes it
    assert srv.sync_change_approvals()["controls_applied"] == [NGHTTP2]
    assert json.loads(srv.remediation_item(NGHTTP2))["exception"]["controls_applied"] is True


def test_unsuccessful_controls_change_is_reported_and_leaves_controls_unapplied():
    sid = _fresh()
    srv.track_remediation(sid)
    srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "", sid)
    _approve(NGHTTP2)
    chg = srv.create_controls_change_request(NGHTTP2)["change_number"]
    srv.mock_advance_change(chg, srv.ChangeState.CLOSED, "approved", "unsuccessful")
    assert srv.sync_change_approvals()["controls_change_failed"] == [NGHTTP2]
    assert json.loads(srv.remediation_item(NGHTTP2))["exception"]["controls_applied"] is False
    assert "change_number" in srv.create_controls_change_request(NGHTTP2)                      # can try again


def test_human_approval_then_applied_controls_lower_the_score_on_next_track():
    from neo_core import exceptions
    sid = _fresh()
    srv.track_remediation(sid)
    score_before = srv._store().get(NGHTTP2).risk_score
    srv.draft_risk_exception(NGHTTP2, ["virtual-patch"], "", sid)
    _approve(NGHTTP2)                                                                       # the human step
    chg = srv.create_controls_change_request(NGHTTP2)["change_number"]
    srv.mock_advance_change(chg, srv.ChangeState.CLOSED, "approved", "successful")         # the person's step
    srv.sync_change_approvals()
    findings, contexts, enrichments = _load_mock(FIXTURE)
    rescored = score_all(findings, exceptions.overlay_contexts(srv._store(), contexts), enrichments)
    srv._SCORED_STORE["scan-2"] = {"scored_findings": [s.model_dump() for s in rescored]}
    assert NGHTTP2 in srv.track_remediation("scan-2", scan_is_complete=True)["rescored"]
    assert srv._store().get(NGHTTP2).risk_score < score_before


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all remediation tool tests passed")
