"""Layer 1 close-out rule: a finding closes on scan evidence, not on "job succeeded".

    absent on a covering re-scan                 -> REMEDIATED
    still present after the window (DEPLOYED)    -> REOPENED + escalated
    exception expired and still present          -> REOPENED + escalated
    present again after REMEDIATED (regression)  -> REOPENED + escalated

Absence only counts if the scan could have seen the resource. Pass `covered` (the
resource IDs the scan actually assessed) so a failed or partial scan cannot
close findings; None means "trust that the scan was complete".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .controls import current_tag
from .exceptions import detect_tag_drift, watch_exceptions
from .remediation import TERMINAL, RemediationItem, State, environment_from_tags, finding_key, new_item, utcnow
from .remediation_store import RemediationStore
from .router import route
from .models import ScoredFinding

DEFAULT_WINDOW = timedelta(hours=24)


@dataclass
class SyncResult:
    opened: list[str] = field(default_factory=list)
    remediated: list[str] = field(default_factory=list)
    reopened: list[str] = field(default_factory=list)
    not_covered: list[str] = field(default_factory=list)
    rerouted: list[str] = field(default_factory=list)    # path C -> A/B: vendor fix appeared
    rescored: list[str] = field(default_factory=list)    # tier changed, e.g. controls applied
    drifted: list[str] = field(default_factory=list)     # exception controls missing from the asset's tag
    drift_cleared: list[str] = field(default_factory=list)


def _evidence(scan_id: str, now: datetime, result: str) -> dict:
    return {"scan_id": scan_id, "at": now.isoformat(), "result": result}


def apply_scan(
    store: RemediationStore,
    present_keys: set[str],
    scan_id: str,
    now: datetime | None = None,
    window: timedelta = DEFAULT_WINDOW,
    covered: set[str] | None = None,
    result: SyncResult | None = None,
) -> SyncResult:
    now = now or utcnow()
    result = result or SyncResult()

    for item in store.list():
        present = item.key in present_keys

        if item.state in TERMINAL:
            if present:  # regression
                item.evidence.append(_evidence(scan_id, now, "present again after remediation"))
                item.move(State.REOPENED, now, escalated=True)
                store.save(item, "regression")
                result.reopened.append(item.item_id)
            continue

        if covered is not None and item.resource_id not in covered:
            result.not_covered.append(item.item_id)
            continue

        if not present:
            item.evidence.append(_evidence(scan_id, now, "absent on re-scan"))
            item.move(State.REMEDIATED, now)
            store.save(item, "closed on scan evidence")
            result.remediated.append(item.item_id)
        elif _overdue(item, now, window):
            item.evidence.append(_evidence(scan_id, now, "still present after window"))
            item.move(State.REOPENED, now, escalated=True)
            store.save(item, "reopened and escalated")
            result.reopened.append(item.item_id)
    return result


def _overdue(item: RemediationItem, now: datetime, window: timedelta) -> bool:
    if item.state is State.DEPLOYED and item.deployed_at:
        return now - datetime.fromisoformat(item.deployed_at) > window
    if item.state is State.EXCEPTION_ACTIVE and item.exception_expires:
        return now > datetime.fromisoformat(item.exception_expires)
    return False


def open_items(
    store: RemediationStore, scored: list[ScoredFinding],
    now: datetime | None = None, result: SyncResult | None = None,
) -> SyncResult:
    """Create a routed, PROPOSED item for every finding not already tracked."""
    now = now or utcnow()
    result = result or SyncResult()
    for sf in scored:
        if store.get_by_key(finding_key(sf.finding)):
            continue
        item = new_item(sf, route(sf.finding), now)
        store.save(item, f"opened, routed to path {item.path.value}")
        result.opened.append(item.item_id)
    return result


def refresh_scores(
    store: RemediationStore, scored: list[ScoredFinding],
    now: datetime | None = None, result: SyncResult | None = None,
) -> SyncResult:
    """Carry a changed tier/score onto the tracked item (SLA due date stays as opened)."""
    now = now or utcnow()
    result = result or SyncResult()
    for sf in scored:
        item = store.get_by_key(finding_key(sf.finding))
        if item is None or item.state in TERMINAL:
            continue
        tag = current_tag(sf.context) or ""
        env, env_source = environment_from_tags(sf.context.tags)
        if env != item.environment and item.state in (State.PROPOSED, State.REOPENED):
            # Only between changes: an item already in a change keeps the environment CAB approved.
            item.environment, item.environment_source = env, env_source
            item.updated_at = now.isoformat()
            store.save(item, f"environment now {env} ({env_source})")
        if (item.tier, item.risk_score) != (sf.tier, sf.risk_score):
            event = f"rescored {item.tier} {item.risk_score} -> {sf.tier} {sf.risk_score}"
            item.tier, item.risk_score, item.controls_tag = sf.tier, sf.risk_score, tag
            item.updated_at = now.isoformat()
            store.save(item, event)
            result.rescored.append(item.item_id)
        elif item.controls_tag != tag:            # tag moved without changing the score
            item.controls_tag = tag
            item.updated_at = now.isoformat()
            store.save(item, f"controls tag now {tag!r}")
    return result


def sync_scan(
    store: RemediationStore, scored: list[ScoredFinding], scan_id: str,
    now: datetime | None = None, window: timedelta = DEFAULT_WINDOW,
    covered: set[str] | None = None,
    observed_tags: dict[str, str | None] | None = None,
) -> SyncResult:
    """One scan cycle: verify tracked items, re-route fixed exceptions, then track new findings.

    observed_tags (resource_id -> raw CompensatingControls value) is what the scan saw on the
    assets. Default: the tags in the scored findings' contexts. Pass it explicitly when scoring
    used overlay_contexts, so the overlay cannot hide a tag that is missing.
    """
    now = now or utcnow()
    present = {finding_key(sf.finding) for sf in scored}
    result = apply_scan(store, present, scan_id, now, window, covered)
    result.rerouted = watch_exceptions(store, scored, now)
    if observed_tags is None:
        observed_tags = {sf.finding.resource_id: current_tag(sf.context) for sf in scored}
    drift = detect_tag_drift(store, observed_tags, now)
    result.drifted, result.drift_cleared = drift.drifted, drift.restored
    refresh_scores(store, scored, now, result)
    return open_items(store, scored, now, result)
