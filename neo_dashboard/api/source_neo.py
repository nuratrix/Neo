"""Neo source: remediation items from the SQLite store that `neo remediate` and the MCP server write.

Read-only: the database is opened with mode=ro, so the dashboard can never change a remediation,
and it does not create the file when it is missing.

An item is shown with:
    tier            P1-P4 and its risk score
    recommendation  the delivery path Neo's router chose (A pull request, B change + patch,
                    C compensating controls + exception), why, and the next step
    suggestions     what the agent advised (record_agent_suggestion), plus what it drafted:
                    the exception's controls and justification
    history         every state change, newest first
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:          # run from a checkout without installing neo_core
    sys.path.insert(0, str(REPO_ROOT))

from neo_core.remediation import RemediationItem, State, TERMINAL  # noqa: E402

TIERS = ("P1", "P2", "P3", "P4")
TIER_NAME = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}
PATHS = ("A", "B", "C")
PATH_NAME = {"A": "Code & images → pull request", "B": "Host patch → ServiceNow change",
             "C": "No vendor fix → compensating controls + exception"}
DUE_SOON = timedelta(days=2)

_NEXT = {
    ("A", State.PROPOSED): "Open a pull request with the fix.",
    ("A", State.IN_REVIEW): "Waiting for code-owner review of the pull request.",
    ("B", State.PROPOSED): "Raise a ServiceNow change (implementation, rollback and test plans).",
    ("B", State.IN_REVIEW): "Waiting for CAB approval of the change.",
    ("B", State.APPROVED): "Approved: the patch executor may run inside the change window.",
    ("B", State.DEPLOYED): "Patched; waiting for a re-scan to confirm before the change is closed.",
    ("C", State.PROPOSED): "No vendor fix: the agent composes compensating controls for the risk owner.",
    ("C", State.IN_REVIEW): "Waiting for the risk owner to approve the exception.",
}


def _recommendation(item: RemediationItem) -> dict:
    p = item.path.value
    target = f" to {item.fixed_version}" if item.fixed_version else ""
    pkg = item.package_name or "the affected package"
    if p == "A":
        headline = f"Open a PR bumping {pkg}{target}"
        why = "A fix exists and the package belongs to code or an image, so it ships through a pull request and CI."
    elif p == "B":
        headline = f"Patch {pkg}{target} on {item.resource_id}"
        why = ("A fix exists and the package is part of a host's OS or installed software, so it needs a "
               "ServiceNow change, CAB approval and a patch window.")
    else:
        headline = "Mitigate with compensating controls"
        why = ("The vendor has no fix yet, so Neo proposes controls and a time-limited risk exception "
               "that a named risk owner must approve.")
    return {"path": p, "path_name": PATH_NAME[p], "headline": headline, "why": why, "next_step": _next_step(item)}


def _next_step(item: RemediationItem) -> str:
    exc = item.exception
    if item.state is State.EXCEPTION_ACTIVE and exc:
        if exc.tag_drift:
            return (f"Controls missing from the asset's tag: {', '.join(exc.tag_drift)}. "
                    f"A person must re-apply them or accept the risk.")
        if exc.controls_applied:
            return f"Exception active until {(item.exception_expires or '')[:10]}; controls are in place."
        if exc.change_ref:
            return f"Exception approved; waiting for {exc.change_ref} to be implemented and closed by a person."
        return "Exception approved; raise the ServiceNow change that implements the controls."
    if item.state is State.REMEDIATED:
        return "Closed on re-scan evidence."
    if item.state is State.REOPENED:
        return "Reopened and escalated: still present after its window, or back after being fixed."
    return _NEXT.get((item.path.value, item.state), "")


def _needs_human(item: RemediationItem) -> bool:
    if item.escalated or item.state in (State.IN_REVIEW, State.REOPENED):
        return True
    exc = item.exception
    return bool(item.state is State.EXCEPTION_ACTIVE and exc and (exc.tag_drift or not exc.controls_applied))


def _sla(item: RemediationItem, now: datetime) -> str:
    if item.state in TERMINAL:
        return "met" if item.sla_met else "missed"
    due = datetime.fromisoformat(item.sla_due)
    return "overdue" if now > due else "due_soon" if due - now <= DUE_SOON else "ok"


def _proposal(item: RemediationItem) -> dict | None:
    """What the agent drafted for a path-C exception, kept apart from free-text suggestions."""
    e = item.exception
    if e is None:
        return None
    return {"status": e.status.value, "controls": e.controls, "effectiveness": e.controls_effectiveness,
            "tag_value": e.tag_value, "justification": e.justification, "approved_by": e.approved_by,
            "expires": e.expires, "controls_applied": e.controls_applied, "change_ref": e.change_ref,
            "tag_drift": e.tag_drift, "warnings": e.tag_warnings}


def _summary(item: RemediationItem, now: datetime) -> dict:
    latest = item.suggestions[-1] if item.suggestions else None
    return {
        "id": item.item_id, "cve_id": item.cve_id,
        "title": f"{item.cve_id} in {item.package_name or 'unknown package'}",
        "resource_id": item.resource_id, "package": item.package_name, "fixed_version": item.fixed_version,
        "tier": item.tier, "tier_name": TIER_NAME.get(item.tier, item.tier), "risk_score": item.risk_score,
        "path": item.path.value, "recommendation": _recommendation(item),
        "state": item.state.value, "needs_human": _needs_human(item), "escalated": item.escalated,
        "sla_due": item.sla_due, "sla_status": _sla(item, now),
        "suggestion": latest, "suggestion_count": len(item.suggestions),
        "has_proposal": item.exception is not None,
        "updated_at": item.updated_at, "created_at": item.created_at,
    }


class NeoSource:
    name = "neo"

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path).resolve()

    def _read(self) -> tuple[list[tuple[RemediationItem, list[tuple[str, str, str]]]], list[str]]:
        if not self.path.is_file():
            return [], [f"{self.path}: no remediation database yet. Run `neo remediate --db <file> sync --mock ...` "
                        f"or point NEO_REMEDIATION_DB at the MCP server's database."]
        try:
            db = sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True)
            try:
                items = [RemediationItem.model_validate_json(b) for (b,) in db.execute("SELECT body FROM items")]
                hist: dict[str, list[tuple[str, str, str]]] = {}
                for iid, at, state, event in db.execute("SELECT item_id, at, state, event FROM history ORDER BY id"):
                    hist.setdefault(iid, []).append((at, state, event))
            finally:
                db.close()
        except (sqlite3.Error, ValueError) as e:
            return [], [f"{self.path}: {e}"]
        return [(i, hist.get(i.item_id, [])) for i in items], []

    @staticmethod
    def _in_window(item: RemediationItem, days: int, now: datetime) -> bool:
        """Open items always show; closed ones only while they are recent."""
        if item.state not in TERMINAL or not item.remediated_at:
            return True
        return datetime.fromisoformat(item.remediated_at) >= now - timedelta(days=days)

    def overview(self, days: int) -> tuple[dict, list[str]]:
        now = datetime.now(timezone.utc)
        rows, errors = self._read()
        items = [_summary(i, now) for i, _ in rows if self._in_window(i, days, now)]
        items.sort(key=lambda s: (TIERS.index(s["tier"]) if s["tier"] in TIERS else 9, -s["risk_score"], s["id"]))
        matrix = {t: {p: sum(1 for s in items if s["tier"] == t and s["path"] == p) for p in PATHS} for t in TIERS}
        return {"items": items, "matrix": matrix,
                "needs_human": sum(1 for s in items if s["needs_human"]),
                "no_suggestion": sum(1 for s in items if not s["suggestion_count"] and s["state"] != "REMEDIATED"),
                "overdue": sum(1 for s in items if s["sla_status"] == "overdue"),
                "generated_at": now.isoformat()}, errors

    def get_item(self, item_id: str) -> tuple[dict | None, list[str]]:
        now = datetime.now(timezone.utc)
        rows, errors = self._read()
        for item, hist in rows:
            if item.item_id != item_id:
                continue
            history = [{"at": at, "state": st, "event": ev} for at, st, ev in reversed(hist)]
            return {
                "summary": _summary(item, now), "suggestions": list(reversed(item.suggestions)),
                "proposal": _proposal(item), "history": history,
                "evidence": {"risk_score": item.risk_score, "tier": item.tier, "cloud": item.cloud_provider,
                             "controls_tag": item.controls_tag, "sla_met": item.sla_met, "links": item.refs,
                             "scan_evidence": item.evidence},
            }, errors
        return None, errors
