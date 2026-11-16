"""ServiceNow change-management client for Path B.

ChangeClient is the interface; MockChangeClient runs offline (NEO_MOCK_MODE) and
ServiceNowClient talks to the Table API with basic auth (SNOW_INSTANCE_URL,
SNOW_USERNAME, SNOW_PASSWORD -- the same variables onprem_context uses for the CMDB).

Things to confirm against your instance before going live (defaults are ServiceNow's
out-of-box values, but instances customise them):
  * change_request.state numeric values        -> DEFAULT_STATE_MAP / state_map=
  * CMDB CI names match what the scanner reports (instance ID vs hostname)
  * closing straight to state 3 may be blocked by your state model (Review first)
  * close_code values: successful | successful_issues | unsuccessful (out-of-box choices)
Anything the instance rejects is raised as ChangeError, never swallowed.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path as FilePath
from typing import Protocol

import httpx
from pydantic import BaseModel

MOCK_MODE: bool = os.getenv("NEO_MOCK_MODE", "true").lower() in {"1", "true", "yes"}


class ChangeError(RuntimeError):
    pass


class ChangeState(str, Enum):
    NEW = "NEW"
    ASSESS = "ASSESS"
    AUTHORIZE = "AUTHORIZE"      # waiting on CAB
    SCHEDULED = "SCHEDULED"      # approved, waiting for the window
    IMPLEMENT = "IMPLEMENT"      # approved and open for implementation
    REVIEW = "REVIEW"
    CLOSED = "CLOSED"
    CANCELED = "CANCELED"


DEFAULT_STATE_MAP = {
    "-5": ChangeState.NEW, "-4": ChangeState.ASSESS, "-3": ChangeState.AUTHORIZE,
    "-2": ChangeState.SCHEDULED, "-1": ChangeState.IMPLEMENT, "0": ChangeState.REVIEW,
    "3": ChangeState.CLOSED, "4": ChangeState.CANCELED,
}


class ChangeRequest(BaseModel):
    """What Neo asks ServiceNow to create. Plans are mandatory: no rollback, no change."""
    type: str = "normal"                  # normal | standard | emergency
    short_description: str
    description: str = ""
    justification: str = ""
    implementation_plan: str
    backout_plan: str
    test_plan: str
    cis: list[str]                        # CMDB CI names the change covers
    impact: str | None = None             # 1 High | 2 Medium | 3 Low
    risk: str | None = None               # None = let ServiceNow's risk calculation decide
    assignment_group: str | None = None   # group name or sys_id
    start_date: datetime
    end_date: datetime


class ChangeRecord(BaseModel):
    number: str
    sys_id: str = ""
    state: ChangeState
    approval: str = ""                    # not requested | requested | approved | rejected
    type: str = "normal"
    start_date: datetime | None = None
    end_date: datetime | None = None
    close_code: str = ""


def close_code(successful: bool, with_issues: bool = False) -> str:
    """ServiceNow close code. "With issues" = some hosts fixed, some rolled back or still vulnerable."""
    if not successful:
        return "unsuccessful"
    return "successful_issues" if with_issues else "successful"


class ChangeClient(Protocol):
    def create_change(self, req: ChangeRequest) -> ChangeRecord: ...
    def get_change(self, number: str) -> ChangeRecord: ...
    def affected_cis(self, number: str) -> list[str]: ...
    def add_work_note(self, number: str, note: str) -> None: ...
    def close_change(self, number: str, successful: bool, notes: str,
                     with_issues: bool = False) -> ChangeRecord: ...


# ---------------------------------------------------------------------------
# Mock (offline; optionally persisted so separate CLI runs share state)
# ---------------------------------------------------------------------------

class MockChangeClient:
    def __init__(self, path: str | None = None):
        self._path = FilePath(path) if path else None
        self._data: dict = {"seq": 30000, "changes": {}}
        if self._path and self._path.exists():
            self._data = json.loads(self._path.read_text())

    def _save(self) -> None:
        if self._path:
            self._path.write_text(json.dumps(self._data, indent=2, default=str))

    def _rec(self, number: str) -> dict:
        try:
            return self._data["changes"][number]
        except KeyError:
            raise ChangeError(f"no such change: {number}") from None

    def _record(self, c: dict) -> ChangeRecord:
        return ChangeRecord(
            number=c["number"], sys_id=c["sys_id"], state=ChangeState(c["state"]),
            approval=c["approval"], type=c["type"], close_code=c.get("close_code", ""),
            start_date=c["start_date"], end_date=c["end_date"],
        )

    def create_change(self, req: ChangeRequest) -> ChangeRecord:
        self._data["seq"] += 1
        number = f"CHG{self._data['seq']:07d}"
        self._data["changes"][number] = {
            "number": number, "sys_id": f"mock-{self._data['seq']}",
            "state": ChangeState.NEW.value, "approval": "not requested", "type": req.type,
            "start_date": req.start_date.isoformat(), "end_date": req.end_date.isoformat(),
            "cis": list(req.cis), "notes": [], "request": req.model_dump(mode="json"),
        }
        self._save()
        return self._record(self._data["changes"][number])

    def get_change(self, number: str) -> ChangeRecord:
        return self._record(self._rec(number))

    def affected_cis(self, number: str) -> list[str]:
        return list(self._rec(number)["cis"])

    def add_work_note(self, number: str, note: str) -> None:
        self._rec(number)["notes"].append(note)
        self._save()

    def close_change(self, number: str, successful: bool, notes: str,
                     with_issues: bool = False) -> ChangeRecord:
        c = self._rec(number)
        c["state"] = ChangeState.CLOSED.value
        c["close_code"] = close_code(successful, with_issues)
        c["notes"].append(notes)
        self._save()
        return self._record(c)

    # -- test / demo helper: stands in for the CAB and the change manager --------
    def set_state(self, number: str, state: ChangeState, approval: str | None = None,
                  close_code: str | None = None) -> None:
        c = self._rec(number)
        c["state"] = state.value
        if approval is not None:
            c["approval"] = approval
        if close_code is not None:
            c["close_code"] = close_code
        self._save()


# ---------------------------------------------------------------------------
# Real client (Table API)
# ---------------------------------------------------------------------------

def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse(s: str) -> datetime | None:
    if not s:
        return None
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


class ServiceNowClient:
    CHANGE = "/api/now/table/change_request"
    TASK_CI = "/api/now/table/task_ci"
    CMDB_CI = "/api/now/table/cmdb_ci"

    def __init__(self, instance_url: str, username: str, password: str,
                 timeout: float = 30.0, state_map: dict[str, ChangeState] | None = None,
                 http: httpx.Client | None = None):
        self._http = http or httpx.Client(
            base_url=instance_url.rstrip("/"), auth=(username, password), timeout=timeout,
            headers={"Accept": "application/json"},
        )
        self._state_map = state_map or DEFAULT_STATE_MAP

    def _call(self, method: str, url: str, **kw) -> dict | list:
        r = self._http.request(method, url, **kw)
        if r.status_code >= 400:
            raise ChangeError(f"ServiceNow {method} {url} -> {r.status_code}: {r.text[:300]}")
        return r.json().get("result", {})

    def _ci_sys_id(self, name: str) -> str:
        rows = self._call("GET", self.CMDB_CI, params={
            "sysparm_query": f"name={name}", "sysparm_fields": "sys_id,name", "sysparm_limit": 1})
        if not rows:
            # Never act on, or approve changes for, a host the CMDB does not know.
            raise ChangeError(f"CI not found in CMDB: {name}")
        return rows[0]["sys_id"]

    def _record(self, row: dict) -> ChangeRecord:
        raw_state = str(row.get("state", ""))
        if raw_state not in self._state_map:
            raise ChangeError(f"unmapped change state {raw_state!r} on {row.get('number')}; "
                              f"pass state_map= for this instance")
        return ChangeRecord(
            number=row["number"], sys_id=row["sys_id"], state=self._state_map[raw_state],
            approval=row.get("approval", ""), type=row.get("type", ""),
            start_date=_parse(row.get("start_date", "")), end_date=_parse(row.get("end_date", "")),
            close_code=row.get("close_code", ""),
        )

    def create_change(self, req: ChangeRequest) -> ChangeRecord:
        ci_ids = [self._ci_sys_id(n) for n in req.cis]      # resolve first: fail before creating
        body = {
            "type": req.type, "short_description": req.short_description,
            "description": req.description, "justification": req.justification,
            "implementation_plan": req.implementation_plan, "backout_plan": req.backout_plan,
            "test_plan": req.test_plan, "cmdb_ci": ci_ids[0],
            "start_date": _fmt(req.start_date), "end_date": _fmt(req.end_date),
        }
        for k in ("impact", "risk", "assignment_group"):
            if getattr(req, k):
                body[k] = getattr(req, k)
        row = self._call("POST", self.CHANGE, json=body,
                         params={"sysparm_exclude_reference_link": "true"})
        for sys_id in ci_ids:                                # affected CIs = the approved patch list
            self._call("POST", self.TASK_CI, json={"task": row["sys_id"], "ci_item": sys_id})
        return self._record(row)

    def _row(self, number: str) -> dict:
        rows = self._call("GET", self.CHANGE, params={
            "sysparm_query": f"number={number}", "sysparm_limit": 1,
            "sysparm_exclude_reference_link": "true"})
        if not rows:
            raise ChangeError(f"no such change: {number}")
        return rows[0]

    def get_change(self, number: str) -> ChangeRecord:
        return self._record(self._row(number))

    def affected_cis(self, number: str) -> list[str]:
        rows = self._call("GET", self.TASK_CI, params={
            "sysparm_query": f"task.number={number}", "sysparm_fields": "ci_item",
            "sysparm_display_value": "true"})
        return [r["ci_item"]["display_value"] if isinstance(r["ci_item"], dict) else r["ci_item"]
                for r in rows]

    def add_work_note(self, number: str, note: str) -> None:
        self._call("PATCH", f"{self.CHANGE}/{self._row(number)['sys_id']}", json={"work_notes": note})

    def close_change(self, number: str, successful: bool, notes: str,
                     with_issues: bool = False) -> ChangeRecord:
        row = self._call("PATCH", f"{self.CHANGE}/{self._row(number)['sys_id']}", json={
            "state": next(k for k, v in self._state_map.items() if v is ChangeState.CLOSED),
            "close_code": close_code(successful, with_issues), "close_notes": notes,
        }, params={"sysparm_exclude_reference_link": "true"})
        return self._record(row)


def get_client(mock_path: str | None = None) -> ChangeClient:
    """Mock under NEO_MOCK_MODE (the default); otherwise the real client from the environment."""
    if MOCK_MODE:
        return MockChangeClient(mock_path)
    missing = [v for v in ("SNOW_INSTANCE_URL", "SNOW_USERNAME", "SNOW_PASSWORD") if not os.getenv(v)]
    if missing:
        raise ChangeError(f"live ServiceNow needs {', '.join(missing)} (or set NEO_MOCK_MODE=true)")
    return ServiceNowClient(os.environ["SNOW_INSTANCE_URL"], os.environ["SNOW_USERNAME"],
                            os.environ["SNOW_PASSWORD"])
