"""Path B: one ServiceNow change per fix group, non-production before production.

A real estate has many hosts with the same vulnerability. CAB reviews one change per fix,
not one per host. Grouping is code, never the agent:

    group key   cloud . fix (package @ fixed_version) . environment
    tier        the highest tier in the group (one P1 host makes it an emergency change)
    size        at most MAX_HOSTS_PER_CHANGE hosts; a larger group is split into several changes
    hosts       one CI per host, even when one fix closes several CVEs on that host

Production and non-production never share a change (CAB rule), and non-production goes first.
A production change may be raised and approved in parallel, but precedence_gate keeps the
executor off every production host until the same fix is patched and healthy on all of the
non-production hosts that have it, and has soaked there for SOAK_HOURS. If no non-production
host has the fix at all, a named person must record a waiver (waive_precedence) -- there is
no agent tool for that.

    plan_groups            PROPOSED/REOPENED path-B items -> ChangeGroups (read-only)
    build_group_request    one ChangeRequest listing every host as an affected CI
    submit_group_change    every item in the group -> IN_REVIEW on the same change number
    precedence_gate        may this production item be patched yet?
    waive_precedence       a person accepts going to production without a non-production run
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .changes import TIER_IMPACT, TIER_TYPE, STALE_RUN_REFS, validate_request
from .remediation import Path, RemediationItem, State, utcnow
from .remediation_store import RemediationStore
from .servicenow import ChangeClient, ChangeRequest

# Policy defaults -- tune per org.
MAX_HOSTS_PER_CHANGE = 50                                 # blast radius and window capacity per change
SOAK_HOURS = {"P1": 4, "P2": 24, "P3": 24, "P4": 24}      # fix runs on non-production this long first
TIER_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

_SNAPSHOT = {
    "aws": "an EBS snapshot of every attached volume",
    "azure": "a VM restore point (managed-disk snapshots)",
    "gcp": "a persistent-disk snapshot",
}


def fix_key(item: RemediationItem) -> tuple[str, str, str]:
    """The same fix: same platform, same package, same target version."""
    return (item.cloud_provider, item.package_name, item.fixed_version)


def _hash(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:10].upper()


@dataclass
class ChangeGroup:
    group_id: str
    cloud_provider: str
    package_name: str
    fixed_version: str
    environment: str                      # prod | nonprod
    tier: str                             # highest tier among the items
    item_ids: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)   # CIs, one per host, sorted
    cve_ids: list[str] = field(default_factory=list)

    @property
    def fix(self) -> str:
        return f"{self.package_name} {self.fixed_version or '(vendor-fixed version)'}"

    def summary(self) -> dict:
        return {"group_id": self.group_id, "environment": self.environment, "tier": self.tier,
                "type": TIER_TYPE.get(self.tier, "normal"), "fix": self.fix, "cloud": self.cloud_provider,
                "hosts": self.hosts, "cves": self.cve_ids, "item_ids": self.item_ids}


def _eligible(item: RemediationItem) -> bool:
    return item.path is Path.B and item.state in (State.PROPOSED, State.REOPENED)


def plan_groups(
    store: RemediationStore, item_ids: list[str] | None = None,
    max_hosts: int = MAX_HOSTS_PER_CHANGE,
) -> list[ChangeGroup]:
    """Group the path-B items waiting for a change. Non-production groups come first."""
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1")
    wanted = set(item_ids) if item_ids is not None else None
    buckets: dict[tuple, list[RemediationItem]] = {}
    for item in store.list():
        if not _eligible(item) or (wanted is not None and item.item_id not in wanted):
            continue
        buckets.setdefault((*fix_key(item), item.environment), []).append(item)

    groups: list[ChangeGroup] = []
    for (cloud, pkg, ver, env), items in buckets.items():
        by_host: dict[str, list[RemediationItem]] = {}
        for it in sorted(items, key=lambda i: (i.resource_id, i.item_id)):
            by_host.setdefault(it.resource_id, []).append(it)
        hosts = sorted(by_host)
        for start in range(0, len(hosts), max_hosts):
            chunk = hosts[start:start + max_hosts]
            members = [it for h in chunk for it in by_host[h]]
            ids = [it.item_id for it in members]
            groups.append(ChangeGroup(
                group_id="GRP-" + _hash(cloud, pkg, ver, env, *ids),
                cloud_provider=cloud, package_name=pkg, fixed_version=ver, environment=env,
                tier=min((it.tier for it in members), key=lambda t: TIER_RANK.get(t, 9)),
                item_ids=ids, hosts=chunk, cve_ids=sorted({it.cve_id for it in members}),
            ))
    # Stable sort: the chunks of one split group keep their host order.
    groups.sort(key=lambda g: (g.environment != "nonprod", TIER_RANK.get(g.tier, 9), g.package_name, g.fixed_version))
    return groups


def find_group(store: RemediationStore, group_id: str, max_hosts: int = MAX_HOSTS_PER_CHANGE) -> ChangeGroup:
    for g in plan_groups(store, max_hosts=max_hosts):
        if g.group_id == group_id:
            return g
    raise ValueError(f"no planned group {group_id} (items may have moved on; plan again)")


def nonprod_changes_for(store: RemediationStore, group: ChangeGroup) -> list[str]:
    """Change numbers that carry this fix on non-production hosts (for the production change text)."""
    key = (group.cloud_provider, group.package_name, group.fixed_version)
    return sorted({i.refs["chg_number"] for i in store.list()
                   if i.environment == "nonprod" and fix_key(i) == key and i.refs.get("chg_number")})


def default_group_plans(group: ChangeGroup, nonprod_changes: list[str] | None = None) -> tuple[str, str, str]:
    """(implementation, backout, test) for a group, used when the agent supplied none."""
    canary = group.hosts[0]
    target = f" to {group.fixed_version}" if group.fixed_version else " to the vendor-fixed version"
    pre = ""
    if group.environment == "prod":
        soak = SOAK_HOURS.get(group.tier, 24)
        evidence = ", ".join(nonprod_changes or []) or "none yet raised"
        pre = (f"0. Precondition: {group.fix} patched and healthy on every non-production host that has it, "
               f"for at least {soak}h (non-production changes: {evidence}). Neo enforces this before any host.\n")
    implementation = (
        f"{pre}1. Confirm the change state is Implement and the window is open.\n"
        f"2. Canary: patch {canary} first, applying the {group.package_name or 'affected'} update{target} "
        f"through the platform's update manager, then health-check it.\n"
        f"3. Patch the remaining {len(group.hosts) - 1} host(s) in waves; each host is snapshotted, patched "
        f"and health-checked before the wave continues.\n"
        f"4. Halt at the first failure: the failed host is rolled back and hosts not yet touched are "
        f"released for a new change.\n"
        f"5. Touch only the CIs listed on this change.")
    snap = _SNAPSHOT.get(group.cloud_provider, "a VM checkpoint / snapshot")
    backout = (
        f"Per host, independently:\n"
        f"1. Take {snap} immediately before patching that host.\n"
        f"2. If its health check fails: uninstall the update (KB uninstall, or yum/dnf history undo).\n"
        f"3. If that does not restore service: restore the host from the snapshot taken in step 1.\n"
        f"Hosts already patched and healthy stay patched unless the owner asks for a full backout.")
    test = (f"Each host: post-patch health check (service responds, no new errors). Then a targeted "
            f"re-scan must show {', '.join(group.cve_ids)} absent on every patched host before the "
            f"change is closed.")
    return implementation, backout, test


def build_group_request(
    group: ChangeGroup, start: datetime, end: datetime,
    implementation: str = "", backout: str = "", test: str = "",
    assignment_group: str | None = None, nonprod_changes: list[str] | None = None,
) -> ChangeRequest:
    d_impl, d_back, d_test = default_group_plans(group, nonprod_changes)
    env = "production" if group.environment == "prod" else "non-production"
    n = len(group.hosts)
    return ChangeRequest(
        type=TIER_TYPE.get(group.tier, "normal"),
        short_description=(f"Patch {group.package_name} to {group.fixed_version or 'fixed version'} on "
                           f"{n} {env} host{'s' if n != 1 else ''} ({group.tier}) [{group.group_id}]"),
        description=(f"Neo fix group {group.group_id}: {group.fix} on {group.cloud_provider}, {env}. "
                     f"CVEs: {', '.join(group.cve_ids)}. Hosts: {', '.join(group.hosts)}. "
                     f"Remediation items: {', '.join(group.item_ids)}."),
        justification=f"{group.tier} vulnerabilities {', '.join(group.cve_ids)} on {n} {env} host(s).",
        implementation_plan=implementation or d_impl, backout_plan=backout or d_back,
        test_plan=test or d_test, cis=list(group.hosts), impact=TIER_IMPACT.get(group.tier),
        assignment_group=assignment_group, start_date=start, end_date=end,
    )


def default_group_window(group: ChangeGroup, now: datetime | None = None) -> tuple[datetime, datetime]:
    """Emergency (P1) opens in an hour, others tomorrow. Window grows with the number of hosts."""
    now = now or utcnow()
    start = now + (timedelta(hours=1) if TIER_TYPE.get(group.tier) == "emergency" else timedelta(days=1))
    return start, start + timedelta(hours=4 + len(group.hosts) // 10)


def submit_group_change(
    store: RemediationStore, client: ChangeClient, group: ChangeGroup, req: ChangeRequest,
    now: datetime | None = None,
) -> list[RemediationItem]:
    """Raise ONE change for the whole group and move every item to IN_REVIEW on it."""
    now = now or utcnow()
    items = []
    for iid in group.item_ids:
        item = store.get(iid)
        if item is None:
            raise ValueError(f"no such item: {iid}")
        if not _eligible(item):
            raise ValueError(f"{iid} is {item.path.value}/{item.state.value}; plan the groups again")
        if fix_key(item) != (group.cloud_provider, group.package_name, group.fixed_version):
            raise ValueError(f"{iid} needs a different fix than group {group.group_id}")
        items.append(item)
    envs = {i.environment for i in items}
    if len(envs) != 1 or envs != {group.environment}:
        raise ValueError("production and non-production hosts must be in separate changes")
    if sorted(set(req.cis)) != sorted(set(group.hosts)):
        raise ValueError("the change's CIs must be exactly the group's hosts, no more and no fewer")
    validate_request(req, now)

    rec = client.create_change(req)
    for item in items:
        refs = {k: v for k, v in item.refs.items() if k not in STALE_RUN_REFS}
        item.move(State.IN_REVIEW, now, refs={**refs, "chg_number": rec.number, "chg_sys_id": rec.sys_id,
                                              "chg_group": group.group_id})
        store.save(item, f"change {rec.number} raised ({req.type}, {group.environment}) for group "
                         f"{group.group_id}: {len(group.hosts)} host(s)")
    return items


@dataclass
class Precedence:
    allowed: bool
    reason: str


def precedence_gate(store: RemediationStore, item: RemediationItem, now: datetime | None = None) -> Precedence:
    """Production waits for non-production. Non-production items always pass."""
    now = now or utcnow()
    if item.environment != "prod":
        return Precedence(True, "non-production host")
    if item.refs.get("nonprod_waiver"):
        return Precedence(True, f"precedence waived: {item.refs['nonprod_waiver']}")
    key = fix_key(item)
    peers = [i for i in store.list()
             if i.path is Path.B and i.environment == "nonprod" and fix_key(i) == key]
    if not peers:
        return Precedence(False, f"no non-production host has {item.package_name} {item.fixed_version}; "
                                 f"a person must record a precedence waiver before production")
    waiting = [i for i in peers if i.state in (State.PROPOSED, State.REOPENED, State.IN_REVIEW, State.APPROVED)
               or i.refs.get("patch_blocked")]
    if waiting:
        return Precedence(False, f"non-production not finished for this fix: "
                                 f"{', '.join(sorted(i.resource_id for i in waiting))}")
    patched = [i for i in peers if i.state in (State.DEPLOYED, State.REMEDIATED) and "patched_at" in i.refs]
    if not patched:
        return Precedence(False, "no non-production host has been patched with this fix yet")
    last = max(datetime.fromisoformat(i.refs["patched_at"]) for i in patched)
    ready = last + timedelta(hours=SOAK_HOURS.get(item.tier, 24))
    if now < ready:
        return Precedence(False, f"non-production soaking until {ready:%Y-%m-%d %H:%M} UTC "
                                 f"({SOAK_HOURS.get(item.tier, 24)}h after the last non-production patch)")
    return Precedence(True, f"non-production patched on {len(patched)} host(s); soak complete")


def waive_precedence(
    store: RemediationStore, item_ids: list[str], approver: str, reason: str,
    now: datetime | None = None,
) -> list[RemediationItem]:
    """A named person accepts patching production without a non-production run. Recorded per item."""
    now = now or utcnow()
    if not approver.strip():
        raise ValueError("a waiver needs a named approver")
    if len(reason.strip()) < 20:
        raise ValueError("a waiver needs a reason of at least 20 characters")
    out = []
    for iid in item_ids:
        item = store.get(iid)
        if item is None:
            raise ValueError(f"no such item: {iid}")
        if item.environment != "prod":
            raise ValueError(f"{iid} is not a production item")
        item.refs = {**item.refs, "nonprod_waiver": f"{approver.strip()} at {now:%Y-%m-%d %H:%M} UTC: {reason.strip()}"}
        item.updated_at = now.isoformat()
        store.save(item, f"non-production precedence waived by {approver.strip()}")
        out.append(item)
    return out
