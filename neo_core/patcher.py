"""Path B: the patch executor, and closing the change on evidence.

    run_patch              APPROVED -> DEPLOYED   gate -> snapshot -> patch -> health check
                           APPROVED -> PROPOSED   anything failed and was rolled back (new change needed)
    close_verified_changes REMEDIATED -> change closed *successful*   (re-scan showed the CVE gone)
                           REOPENED   -> change closed *unsuccessful* (still/again present)

Rules this module enforces:
  * It only touches hosts execution_gate returns, re-checked after the snapshot (a slow snapshot
    must not carry the run past the change window).
  * A successful patch run is NOT remediation. The item becomes DEPLOYED; only a re-scan closes it
    (closeout.apply_scan), and only then is the ServiceNow change closed as successful.
  * Every step leaves a work note on the change.
  * Nothing here talks to a cloud: a PatchBackend does. Only a mock backend exists today.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from .changes import execution_gate
from .remediation import Path, RemediationItem, State, utcnow
from .remediation_store import RemediationStore
from .servicenow import ChangeClient, ChangeError

# Package and version end up in a command line on a host; accept only what package managers allow.
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:~-]{0,127}$")


DEFAULT_STEP_TIMEOUT = 900.0     # seconds per backend step; policy default, tune per org


class StepTimeout(RuntimeError):
    pass


def _timed(fn, timeout: float | None, label: str):
    """Run one backend call with a time limit. A hung call cannot be killed, only abandoned."""
    if not timeout:
        return fn()
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(fn).result(timeout)
    except _FutureTimeout:
        raise StepTimeout(f"{label} did not finish within {timeout:g}s") from None
    finally:
        pool.shutdown(wait=False)


class PatchBackend(Protocol):
    """Does the real work on one host. Each method raises on failure; the executor handles it."""
    def snapshot(self, instance_id: str) -> str: ...                       # returns a snapshot reference
    def apply(self, instance_id: str, package: str, version: str) -> str: ...   # returns output/log
    def health_check(self, instance_id: str) -> str: ...                   # raises if unhealthy
    def rollback(self, instance_id: str, snapshot_ref: str) -> str: ...


class MockPatchBackend:
    """Offline backend. fail_at is one of snapshot | apply | health | rollback (rollback implies a health failure)."""

    def __init__(self, fail_at: str | None = None):
        if fail_at not in (None, "snapshot", "apply", "health", "rollback"):
            raise ValueError(f"unknown failure point: {fail_at}")
        self.fail_at = fail_at
        self.calls: list[tuple[str, str]] = []

    def _call(self, step: str, host: str) -> None:
        self.calls.append((step, host))

    def snapshot(self, instance_id: str) -> str:
        self._call("snapshot", instance_id)
        if self.fail_at == "snapshot":
            raise RuntimeError("mock: snapshot failed")
        return f"snap-mock-{instance_id}"

    def apply(self, instance_id: str, package: str, version: str) -> str:
        self._call("apply", instance_id)
        if self.fail_at == "apply":
            raise RuntimeError("mock: package manager exited 1")
        return f"mock: {package} -> {version or 'latest fixed'}"

    def health_check(self, instance_id: str) -> str:
        self._call("health", instance_id)
        if self.fail_at in ("health", "rollback"):
            raise RuntimeError("mock: service not responding after patch")
        return "mock: healthy"

    def rollback(self, instance_id: str, snapshot_ref: str) -> str:
        self._call("rollback", instance_id)
        if self.fail_at == "rollback":
            raise RuntimeError("mock: rollback failed")
        return f"mock: restored from {snapshot_ref}"


@dataclass
class PatchRun:
    item_id: str
    outcome: str                       # deployed | dry-run | refused | rolled-back | needs-human
    detail: str = ""
    steps: list[str] = field(default_factory=list)


def _note(client: ChangeClient, number: str, text: str, run: PatchRun) -> None:
    run.steps.append(text)
    try:
        client.add_work_note(number, f"[Neo patcher] {text}")
    except ChangeError:       # a note failing must not abort or hide a patch run
        run.steps.append("(work note could not be written)")


def run_patch(
    store: RemediationStore, client: ChangeClient, backend: PatchBackend, item_id: str,
    dry_run: bool = False, now: datetime | None = None, step_timeout: float | None = DEFAULT_STEP_TIMEOUT,
) -> PatchRun:
    fixed_clock = now                    # tests pin the time; live runs read the clock each step
    now = now or utcnow()
    item = store.get(item_id)
    if item is None:
        raise ValueError(f"no such item: {item_id}")
    if item.path is not Path.B:
        return PatchRun(item_id, "refused", f"on path {item.path.value}, not B")
    if item.refs.get("patch_blocked"):
        return PatchRun(item_id, "refused", f"blocked for a person: {item.refs['patch_blocked']}")

    gate = execution_gate(client, item, now)
    if not gate.allowed:
        return PatchRun(item_id, "refused", gate.reason)
    if not (_SAFE.match(item.package_name or "") and (not item.fixed_version or _SAFE.match(item.fixed_version))):
        return PatchRun(item_id, "refused", "package or version has characters a package manager would not use")
    host = gate.instance_ids[0]
    number = item.refs["chg_number"]
    if dry_run:
        return PatchRun(item_id, "dry-run", f"would snapshot, patch {item.package_name} to "
                        f"{item.fixed_version or 'the fixed version'} and health-check {host} under {number}")

    run = PatchRun(item_id, "refused")
    _note(client, number, f"starting on {host}", run)

    try:
        snap = _timed(lambda: backend.snapshot(host), step_timeout, "snapshot")
    except Exception as e:                      # nothing has changed yet: leave the item APPROVED
        _note(client, number, f"snapshot failed, host untouched: {e}", run)
        run.outcome, run.detail = "refused", f"snapshot failed: {e}"
        return run
    _note(client, number, f"snapshot {snap}", run)

    again = execution_gate(client, item, fixed_clock or utcnow())
    if not again.allowed:                       # e.g. the snapshot ran past the window
        _note(client, number, f"stopped before patching: {again.reason}", run)
        run.outcome, run.detail = "refused", again.reason
        return run

    try:
        out = _timed(lambda: backend.apply(host, item.package_name, item.fixed_version), step_timeout, "patch")
        _note(client, number, f"applied: {out}", run)
    except StepTimeout as e:
        # The package manager may still be running. Rolling back underneath it could corrupt the
        # host, so stop and let a person look.
        return _block(store, client, item, number, f"{e}; host state unknown", run, now)
    except Exception as e:
        return _roll_back(store, client, backend, item, host, snap, number, str(e), run, now, step_timeout)
    try:
        _note(client, number, f"health check: {_timed(lambda: backend.health_check(host), step_timeout, 'health check')}", run)
    except Exception as e:
        return _roll_back(store, client, backend, item, host, snap, number, str(e), run, now, step_timeout)

    item.refs = {**item.refs, "patched_at": now.isoformat(), "snapshot": snap}
    item.move(State.DEPLOYED, now)
    store.save(item, f"patched {host} under {number}; waiting for a re-scan to confirm")
    _note(client, number, "patched and healthy; awaiting re-scan evidence before the change is closed", run)
    run.outcome = "deployed"
    return run


def _block(store, client, item: RemediationItem, number, why, run, now) -> PatchRun:
    item.refs = {**item.refs, "patch_blocked": why}
    item.escalated = True
    item.updated_at = now.isoformat()
    store.save(item, f"patch run stopped, needs a person: {why}")
    _note(client, number, f"STOPPED: {why}. Manual check needed; change left open.", run)
    run.outcome, run.detail = "needs-human", why
    return run


def _roll_back(store, client, backend, item: RemediationItem, host, snap, number, why, run, now,
               step_timeout=None) -> PatchRun:
    _note(client, number, f"failed: {why}; rolling back", run)
    try:
        _note(client, number, f"rollback: {_timed(lambda: backend.rollback(host, snap), step_timeout, 'rollback')}", run)
    except Exception as e:
        # The host may be half-patched. Do not guess: stop and hand it to a person.
        return _block(store, client, item, number, f"rollback failed on {host}: {e}", run, now)
    try:
        client.close_change(number, False, f"Patch failed ({why}); rolled back to {snap}.")
    except ChangeError as e:
        run.steps.append(f"(could not close {number}: {e})")
    item.refs = {k: v for k, v in item.refs.items() if k not in ("chg_number", "chg_sys_id")}
    item.move(State.PROPOSED, now)
    store.save(item, f"patch failed and rolled back; {number} closed unsuccessful")
    run.outcome, run.detail = "rolled-back", why
    return run


def run_patch_batch(
    store: RemediationStore, client: ChangeClient, backend: PatchBackend, item_ids: list[str],
    dry_run: bool = False, now: datetime | None = None, step_timeout: float | None = DEFAULT_STEP_TIMEOUT,
) -> list[PatchRun]:
    """Patch several items one at a time, halting at the first failure.

    The first host is the canary: if it rolls back, needs a person, or hits a snapshot error, the
    rest are not touched. Hosts the gate simply refuses (outside their window, wrong change state)
    are skipped without stopping the batch, since each has its own change. Dry runs never halt.
    """
    runs: list[PatchRun] = []
    halted = ""
    for iid in item_ids:
        if halted:
            runs.append(PatchRun(iid, "skipped", f"batch halted: {halted}"))
            continue
        run = run_patch(store, client, backend, iid, dry_run, now, step_timeout)
        runs.append(run)
        failed = run.outcome in ("rolled-back", "needs-human") or (
            run.outcome == "refused" and run.detail.startswith("snapshot failed"))
        if failed and not dry_run:
            halted = f"{iid} {run.outcome}"
    return runs


@dataclass
class CloseResult:
    successful: list[str] = field(default_factory=list)
    unsuccessful: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def close_verified_changes(
    store: RemediationStore, client: ChangeClient, now: datetime | None = None,
) -> CloseResult:
    """Close path-B changes once scan evidence decides the outcome. Idempotent per change number."""
    now = now or utcnow()
    out = CloseResult()
    for state, ok in ((State.REMEDIATED, True), (State.REOPENED, False)):
        for item in store.list(state):
            number = item.refs.get("chg_number")
            if item.path is not Path.B or not number or item.refs.get("chg_closed") == number:
                continue
            if "patched_at" not in item.refs:       # fixed some other way: not this change's doing
                continue
            last = item.evidence[-1] if item.evidence else {}
            where = f"scan {last.get('scan_id')} ({last.get('at', '')[:19]}): {last.get('result', '')}"
            notes = (f"{item.cve_id} absent on re-scan: {where}. Closing successful." if ok
                     else f"{item.cve_id} still present: {where}. Closing unsuccessful; item reopened.")
            try:
                client.close_change(number, ok, notes)
            except ChangeError as e:
                out.errors[item.item_id] = str(e)
                continue
            item.refs = {**item.refs, "chg_closed": number}
            item.updated_at = now.isoformat()
            store.save(item, f"{number} closed {'successful' if ok else 'unsuccessful'} on scan evidence")
            (out.successful if ok else out.unsuccessful).append(item.item_id)
    return out
