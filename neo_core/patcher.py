"""Path B: the patch executor, and closing the change on evidence.

    run_patch              APPROVED -> DEPLOYED   gate -> precedence -> snapshot -> patch -> health check
                           APPROVED -> PROPOSED   anything failed and was rolled back (new change needed)
    run_change             one change, many hosts: canary first, then waves, halting at the first failure
    close_verified_changes closes each change once every host on it has an outcome:
                           all fixed on re-scan -> successful; some -> successful_issues; none -> unsuccessful

Rules this module enforces:
  * It only touches hosts execution_gate returns, re-checked after the snapshot (a slow snapshot
    must not carry the run past the change window).
  * A successful patch run is NOT remediation. The item becomes DEPLOYED; only a re-scan closes it
    (closeout.apply_scan), and only then is the ServiceNow change closed as successful.
  * Every step leaves a work note on the change.
  * A production host is not touched until change_groups.precedence_gate passes: the same fix
    patched and healthy on non-production first, and soaked.
  * One host failing does not close a shared change: that host is rolled back and released, and
    the change closes when every host on it has an outcome (settle_change).
  * Nothing here talks to a cloud: a PatchBackend does. Only a mock backend exists today.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from .change_groups import precedence_gate
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
    """Offline backend. fail_at is one of snapshot | apply | health | rollback (rollback implies a
    health failure). fail_hosts limits the failure to those hosts; None = every host fails."""

    def __init__(self, fail_at: str | None = None, fail_hosts: set[str] | None = None):
        if fail_at not in (None, "snapshot", "apply", "health", "rollback"):
            raise ValueError(f"unknown failure point: {fail_at}")
        self._fail_at = fail_at
        self.fail_hosts = set(fail_hosts) if fail_hosts else None
        self._host = ""
        self.calls: list[tuple[str, str]] = []

    @property
    def fail_at(self) -> str | None:
        if self.fail_hosts is not None and self._host not in self.fail_hosts:
            return None
        return self._fail_at

    def _call(self, step: str, host: str) -> None:
        self._host = host
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
    order = precedence_gate(store, item, now)
    if not order.allowed:
        return PatchRun(item_id, "refused", order.reason)
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
    _release(store, item, number, "rolled_back_under", now, f"patch failed and rolled back under {number}")
    try:
        closed = settle_change(store, client, number, now)
    except ChangeError as e:
        closed = None
        run.steps.append(f"(could not close {number}: {e})")
    if closed:
        run.steps.append(f"{number} closed {closed}")
    run.outcome, run.detail = "rolled-back", why
    return run


def _release(store, item: RemediationItem, number: str, why_key: str, now, event: str) -> None:
    """Take an item off a change it can no longer finish under; it needs a new change."""
    item.refs = {**{k: v for k, v in item.refs.items() if k not in ("chg_number", "chg_sys_id", "chg_group")},
                 why_key: number}
    item.move(State.PROPOSED, now)
    store.save(item, event)


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
class ChangeRun:
    change_number: str
    waves: list[list[PatchRun]] = field(default_factory=list)
    halted: str = ""
    released: list[str] = field(default_factory=list)     # untouched items freed for a new change
    closed: str | None = None                             # close code, if the change closed during the run

    @property
    def runs(self) -> list[PatchRun]:
        return [r for w in self.waves for r in w]


DEFAULT_WAVE_SIZE = 5           # hosts per wave after the canary; policy default, tune per org


def run_change(
    store: RemediationStore, client: ChangeClient, backend: PatchBackend, number: str,
    wave_size: int = DEFAULT_WAVE_SIZE, dry_run: bool = False, now: datetime | None = None,
    step_timeout: float | None = DEFAULT_STEP_TIMEOUT,
) -> ChangeRun:
    """Patch every approved host on one change: one canary host, then waves of wave_size.

    Halts at the first host that rolls back, needs a person, or cannot be snapshotted. Hosts not
    yet touched are then released (back to PROPOSED) for a new change, and a work note records
    why. When several items share a host (one fix closing several CVEs) the host is patched once.
    """
    if wave_size < 1:
        raise ValueError("wave_size must be at least 1")
    now_ = now or utcnow()
    out = ChangeRun(number)
    items = [i for i in store.list(State.APPROVED) if i.path is Path.B and i.refs.get("chg_number") == number]
    if not items:
        out.halted = f"no APPROVED items on {number}"
        return out
    by_host: dict[str, list[RemediationItem]] = {}
    for it in sorted(items, key=lambda i: (i.resource_id, i.item_id)):
        by_host.setdefault(it.resource_id, []).append(it)
    hosts = sorted(by_host)
    waves = [hosts[:1]] + [hosts[i:i + wave_size] for i in range(1, len(hosts), wave_size)]

    for w, wave in enumerate(waves):
        if out.halted:
            break
        results = []
        for host in wave:
            primary, *siblings = by_host[host]
            run = run_patch(store, client, backend, primary.item_id, dry_run, now, step_timeout)
            results.append(run)
            if not dry_run:
                _mirror(store, primary.item_id, siblings, run, number, now_)
            failed = run.outcome in ("rolled-back", "needs-human") or (
                run.outcome == "refused" and run.detail.startswith("snapshot failed"))
            if failed and not dry_run:
                out.halted = f"{'canary' if w == 0 else f'wave {w}'} host {host} {run.outcome}: {run.detail}"
                break
        out.waves.append(results)

    if out.halted and not dry_run and not out.halted.startswith("no APPROVED"):
        touched = {r.item_id for r in out.runs}
        for host in hosts:
            for it in by_host[host]:
                cur = store.get(it.item_id)
                if cur.state is State.APPROVED and cur.item_id not in touched and host not in {
                        store.get(r.item_id).resource_id for r in out.runs}:
                    _release(store, cur, number, "halted_under", now_, f"not patched: {number} halted ({out.halted})")
                    out.released.append(cur.item_id)
        try:
            client.add_work_note(number, f"[Neo patcher] halted: {out.halted}. "
                                         f"{len(out.released)} untouched item(s) released for a new change.")
        except ChangeError:
            pass
        try:
            out.closed = settle_change(store, client, number, now_)
        except ChangeError:
            pass
    return out


def _mirror(store, primary_id: str, siblings: list[RemediationItem], run: PatchRun, number: str, now) -> None:
    """Items on the same host and fix share the host's outcome: it was patched (or not) once."""
    if not siblings:
        return
    primary = store.get(primary_id)
    for sib in siblings:
        sib = store.get(sib.item_id)
        if sib.state is not State.APPROVED:
            continue
        if run.outcome == "deployed":
            sib.refs = {**sib.refs, "patched_at": primary.refs["patched_at"], "snapshot": primary.refs["snapshot"]}
            sib.move(State.DEPLOYED, now)
            store.save(sib, f"patched with {primary.item_id} on {sib.resource_id} under {number}; awaiting re-scan")
        elif run.outcome == "rolled-back":
            _release(store, sib, number, "rolled_back_under", now, f"rolled back with {primary.item_id} under {number}")
        elif run.outcome == "needs-human":
            sib.refs = {**sib.refs, "patch_blocked": primary.refs.get("patch_blocked", "host needs a person")}
            sib.escalated = True
            sib.updated_at = now.isoformat()
            store.save(sib, f"blocked with {primary.item_id}: host needs a person")


@dataclass
class CloseResult:
    successful: list[str] = field(default_factory=list)       # item IDs on changes closed successful
    unsuccessful: list[str] = field(default_factory=list)
    with_issues: list[str] = field(default_factory=list)      # changes where only some hosts were fixed
    errors: dict[str, str] = field(default_factory=dict)


_OPEN = (State.IN_REVIEW, State.APPROVED, State.DEPLOYED)


def settle_change(
    store: RemediationStore, client: ChangeClient, number: str, now: datetime | None = None,
) -> str | None:
    """Close a change once every host on it has an outcome. Returns the close code, or None if not yet.

    On the change: items still on it (REMEDIATED / REOPENED) plus items released from it
    (rolled back, or untouched after a halt). Successful = every patched host fixed on re-scan and
    nothing released; successful_issues = some fixed; unsuccessful = none fixed.
    """
    now = now or utcnow()
    every = store.list()
    on = [i for i in every if i.path is Path.B and i.refs.get("chg_number") == number]
    released = [i for i in every if number in (i.refs.get("rolled_back_under"), i.refs.get("halted_under"))]
    if any(i.state in _OPEN for i in on) or any(i.refs.get("chg_closed") == number for i in on):
        return None
    if not on and not released:
        return None
    fixed = [i for i in on if i.state is State.REMEDIATED and "patched_at" in i.refs]
    reopened = [i for i in on if i.state is State.REOPENED and "patched_at" in i.refs]
    if not fixed and not reopened and not released:
        return None                                  # nothing this change did; fixed some other way
    ok, issues = bool(fixed), bool(fixed) and bool(reopened or released)
    lines = []
    for i in fixed:
        last = i.evidence[-1] if i.evidence else {}
        lines.append(f"{i.resource_id} {i.cve_id}: absent on scan {last.get('scan_id')} ({last.get('at', '')[:19]})")
    lines += [f"{i.resource_id} {i.cve_id}: still present on re-scan; item reopened" for i in reopened]
    lines += [f"{i.resource_id} {i.cve_id}: rolled back, needs a new change" for i in released
              if i.refs.get("rolled_back_under") == number]
    lines += [f"{i.resource_id} {i.cve_id}: not patched (run halted), needs a new change" for i in released
              if i.refs.get("halted_under") == number]
    verdict = "successful with issues" if issues else ("successful" if ok else "unsuccessful")
    client.close_change(number, ok, f"Closing {verdict} on evidence:\n" + "\n".join(lines), with_issues=issues)
    for i in on:
        i.refs = {**i.refs, "chg_closed": number}
        i.updated_at = now.isoformat()
        store.save(i, f"{number} closed {verdict} on scan evidence")
    return "successful_issues" if issues else ("successful" if ok else "unsuccessful")


def close_verified_changes(
    store: RemediationStore, client: ChangeClient, now: datetime | None = None,
) -> CloseResult:
    """Close every path-B change whose hosts all have an outcome. Idempotent per change number."""
    now = now or utcnow()
    out = CloseResult()
    numbers = sorted({i.refs["chg_number"] for i in store.list()
                      if i.path is Path.B and i.refs.get("chg_number")
                      and i.state in (State.REMEDIATED, State.REOPENED)})
    for number in numbers:
        try:
            code = settle_change(store, client, number, now)
        except ChangeError as e:
            for i in store.list():
                if i.refs.get("chg_number") == number:
                    out.errors[i.item_id] = str(e)
            continue
        if code is None:
            continue
        ids = [i.item_id for i in store.list() if i.refs.get("chg_number") == number]
        {"successful": out.successful, "unsuccessful": out.unsuccessful,
         "successful_issues": out.with_issues}[code].extend(ids)
    return out
