"""Build a demo remediation database so the dashboard has something to show (no AWS, no network).

    uv run python seed_demo.py ../demo.db
    $env:NEO_REMEDIATION_DB = "../demo.db"; uv run uvicorn app:app --port 8787

It drives the real Neo code (mock scan, mock ServiceNow, mock patch backend), so what you see is what
`neo remediate` would have written: a P1 host patched and then closed on re-scan evidence, a change waiting for CAB,
and an exception approved and waiting for a person to implement its controls.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from neo_core import changes, exceptions, patcher                      # noqa: E402
from neo_core.cli import _load_mock                                    # noqa: E402
from neo_core.closeout import sync_scan                                # noqa: E402
from neo_core.remediation import Path as RPath, State                  # noqa: E402
from neo_core.remediation_store import SqliteStore                     # noqa: E402
from neo_core.risk_engine import score_all                             # noqa: E402
from neo_core.servicenow import ChangeState, MockChangeClient          # noqa: E402

FIXTURES = REPO / "neo_core" / "examples"


def seed(db_path: str | Path) -> SqliteStore:
    db = Path(db_path)
    for p in (db, Path(f"{db}.snow.json")):
        p.unlink(missing_ok=True)
    store, snow = SqliteStore(str(db)), MockChangeClient(f"{db}.snow.json")
    now = datetime.now(timezone.utc)

    findings, contexts, enrichments = _load_mock(str(FIXTURES / "mock_findings.json"))
    more_f, more_c, more_e = _load_mock(str(FIXTURES / "mock_findings_multi_source.json"))
    findings, contexts, enrichments = findings + more_f, {**contexts, **more_c}, {**enrichments, **more_e}
    sync_scan(store, score_all(findings, contexts, enrichments), "demo-scan-1", now - timedelta(days=3))

    items = store.list()
    path_b = sorted((i for i in items if i.path is RPath.B and i.resource_id.startswith("i-0")), key=lambda i: i.tier)
    path_c = [i for i in items if i.path is RPath.C]

    if path_b:      # P1 host patch: CAB approved, patched, waiting for the re-scan
        item = path_b[0]
        changes.submit_change(store, snow, item.item_id, changes.build_request(
            item, [item.resource_id], now - timedelta(hours=3), now + timedelta(hours=1)), now - timedelta(days=2))
        num = store.get(item.item_id).refs["chg_number"]
        snow.set_state(num, ChangeState.SCHEDULED, "approved")
        changes.sync_changes(store, snow, now - timedelta(days=1))
        snow.set_state(num, ChangeState.IMPLEMENT)
        patcher.run_patch(store, snow, patcher.MockPatchBackend(), item.item_id, now=now - timedelta(hours=2))

    if len(path_b) > 1:     # a second host change still waiting for CAB
        item = path_b[1]
        start = now + timedelta(days=1)
        changes.submit_change(store, snow, item.item_id, changes.build_request(
            item, [item.resource_id], start, start + timedelta(hours=4)), now - timedelta(hours=6))

    if path_c:      # no vendor fix: controls drafted and approved, change raised, waiting on implementation
        item = path_c[0]
        exceptions.draft_exception(store, item.item_id, ["virtual-patch", "sg-restricted"],
                                   "No vendor patch; WAF virtual patch and a restricted security group.", now - timedelta(days=1))
        exceptions.approve_exception(store, item.item_id, "demo.risk.owner", now + timedelta(days=21), now - timedelta(hours=20))
        exceptions.request_controls_change(store, snow, item.item_id, now + timedelta(days=1),
                                           now + timedelta(days=1, hours=2), now=now - timedelta(hours=18))

    # A re-scan in which the P1 finding is gone and everything else is still there.
    gone = {i.key for i in store.list(State.DEPLOYED)}
    scored = [s for s in score_all(findings, contexts, enrichments)
              if f"{s.finding.resource_id}|{s.finding.cve_id}|{s.finding.package_name}" not in gone]
    sync_scan(store, scored, "demo-scan-2", now - timedelta(hours=1), covered={s.finding.resource_id for s in scored} | {i.resource_id for i in store.list(State.DEPLOYED)})
    patcher.close_verified_changes(store, snow, now)
    _demo_suggestions(store, now)
    return store


def _demo_suggestions(store: SqliteStore, now: datetime) -> None:
    """Stand-in for what the agent records with record_agent_suggestion. P1-P3 get advice, P4 does
    not, so the dashboard shows both. Demo text only."""
    for item in store.list():
        if item.tier == "P4" or item.state is State.REMEDIATED:
            continue
        pkg = item.package_name or "the package"
        to = f" to {item.fixed_version}" if item.fixed_version else ""
        if item.path is RPath.A:
            kind, text = "fix", f"Path A: bump {pkg}{to} in the repo or base image, let CI re-scan the dependencies, and have the code owner review the PR."
        elif item.path is RPath.B:
            kind, text = "path", (f"Path B: patch {pkg}{to} on {item.resource_id} in the next change window. Snapshot first; "
                                  f"after patching check the service responds, then confirm {item.cve_id} is gone on the re-scan.")
        else:
            kind, text = "controls", (f"Path C: the vendor has no fix for {item.cve_id}. Propose virtual-patch and sg-restricted, "
                                      f"expiring in 30 days, and ask the risk owner to approve before any change is raised.")
        item.suggestions = [{"at": now.isoformat(), "author": "demo", "kind": kind, "text": text}]
        store.save(item, f"agent suggestion recorded ({kind})")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(REPO / "neo_dashboard" / "demo.db")
    s = seed(out)
    for it in s.list():
        print(f"{it.item_id}  {it.tier}  path {it.path.value}  {it.state.value:<16} {it.cve_id}  {it.resource_id}")
    print(f"wrote {out}")
