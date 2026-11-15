"""Project Neo CLI.

AWS (Inspector v2 — default):
  neo scan --cloud aws --region us-east-1 --profile prod --out ./out

AWS (Security Hub aggregator):
  neo scan --cloud aws --source securityhub --region us-east-1 --out ./out

AWS Org-wide (cross-account exposure resolution):
  neo scan --cloud aws --assume-role-name NeoReadOnly --out ./out

Azure (Defender for Cloud):
  neo scan --cloud azure --subscription-id <sub-id> --out ./out

GCP (Security Command Center):
  neo scan --cloud gcp --project-id my-project --out ./out

On-prem via Nessus:
  neo scan --cloud onprem --source nessus \\
      --scanner-url https://nessus-host:8834 \\
      --context-map ./context_map.json --out ./out

On-prem via Qualys:
  neo scan --cloud onprem --source qualys \\
      --scanner-url https://qualysapi.qualys.com --out ./out

On-prem via Rapid7:
  neo scan --cloud onprem --source rapid7 \\
      --scanner-url https://console:3780 --out ./out

Mock mode (no credentials needed — any cloud):
  neo scan --cloud aws --mock "neo_core/examples/mock_findings.json" --out ./out
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import timedelta

from . import changes, controls, exceptions, patcher, reporter, servicenow
from .closeout import sync_scan
from .models import AssetContext, Enrichment, Finding
from .remediation import IllegalTransition, State, utcnow
from .remediation_store import SqliteStore
from .risk_engine import score_all
from .servicenow import ChangeError, ChangeState


# ---------------------------------------------------------------------------
# Mock fixture loader (shared across all clouds)
# ---------------------------------------------------------------------------

def _load_mock(path: str):
    with open(path) as fh:
        data = json.load(fh)
    findings = [Finding(**f) for f in data["findings"]]
    contexts = {c["resource_id"]: AssetContext(**c) for c in data.get("contexts", [])}
    enrichments = {e["cve_id"]: Enrichment(**e) for e in data.get("enrichments", [])}
    return findings, contexts, enrichments


# ---------------------------------------------------------------------------
# Cloud-specific live dispatch
# ---------------------------------------------------------------------------

def _live_aws(args) -> tuple:
    from . import aws_context, enrich
    if args.source == "securityhub":
        from . import aws_securityhub as ingest
    else:
        from . import aws_inspector as ingest

    findings = ingest.pull_findings(region=args.region, profile=args.profile)
    contexts = aws_context.build_contexts(
        findings,
        region=args.region,
        profile=args.profile,
        assume_role_name=args.assume_role_name,
    )
    enrichments = enrich.build_enrichments([f.cve_id for f in findings if f.cve_id])
    return findings, contexts, enrichments


def _live_azure(args) -> tuple:
    from . import azure_context, azure_defender, enrich

    findings = azure_defender.pull_findings(
        subscription_id=args.subscription_id,
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET"),
    )
    contexts = azure_context.build_contexts(
        findings,
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET"),
    )
    enrichments = enrich.build_enrichments([f.cve_id for f in findings if f.cve_id])
    return findings, contexts, enrichments


def _live_gcp(args) -> tuple:
    from . import enrich, gcp_context, gcp_scc

    findings = gcp_scc.pull_findings(
        project_id=args.project_id,
        credentials_path=args.gcp_credentials,
    )
    contexts = gcp_context.build_contexts(
        findings,
        credentials_path=args.gcp_credentials,
    )
    enrichments = enrich.build_enrichments([f.cve_id for f in findings if f.cve_id])
    return findings, contexts, enrichments


def _live_onprem(args) -> tuple:
    from . import enrich, onprem_context

    source = args.source or "nessus"
    if source == "qualys":
        from . import qualys as ingest  # type: ignore[assignment]
        findings = ingest.pull_findings(
            scanner_url=args.scanner_url,
            username=os.getenv("QUALYS_USERNAME"),
            password=os.getenv("QUALYS_PASSWORD"),
        )
    elif source == "rapid7":
        from . import rapid7 as ingest  # type: ignore[assignment]
        findings = ingest.pull_findings(
            scanner_url=args.scanner_url,
            username=os.getenv("RAPID7_USERNAME"),
            password=os.getenv("RAPID7_PASSWORD"),
        )
    else:  # nessus (default)
        from . import nessus as ingest  # type: ignore[assignment]
        findings = ingest.pull_findings(
            scanner_url=args.scanner_url,
            access_key=os.getenv("NESSUS_ACCESS_KEY"),
            secret_key=os.getenv("NESSUS_SECRET_KEY"),
        )

    contexts = onprem_context.build_contexts(
        findings,
        context_map_path=args.context_map,
        snow_instance_url=os.getenv("SNOW_INSTANCE_URL"),
        snow_username=os.getenv("SNOW_USERNAME"),
        snow_password=os.getenv("SNOW_PASSWORD"),
    )
    enrichments = enrich.build_enrichments([f.cve_id for f in findings if f.cve_id])
    return findings, contexts, enrichments


_LIVE_DISPATCH = {
    "aws":    _live_aws,
    "azure":  _live_azure,
    "gcp":    _live_gcp,
    "onprem": _live_onprem,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _exception(store, args) -> None:
    c = args.ecmd
    if c == "draft":
        item = exceptions.draft_exception(store, args.item_id, args.control, args.justification)
        exc = item.exception
        print(f"{item.item_id}: exception {exc.exception_id} drafted, awaiting approval")
        print(f"  controls {', '.join(exc.controls)}  combined effect {exc.controls_effectiveness}")
        print(f"  the change will set the tag: CompensatingControls={exc.tag_value}")
        print(f"  {controls.tag_command(item.cloud_provider, item.resource_id, exc.tag_value)}")
        for w in exc.tag_warnings:
            print(f"  warning: {w}")
        print(f"  next: risk owner approves; then `exception change {item.item_id}` raises the "
              f"ServiceNow change")
    elif c == "approve":
        now = utcnow()
        item = exceptions.approve_exception(store, args.item_id, args.approver,
                                            now + timedelta(days=args.days), now)
        print(f"{item.item_id}: exception active until {item.exception_expires}")
    elif c == "controls":
        for ctl in controls.CATALOG.values():
            print(f"{ctl.id:<20} {ctl.weight:.2f}  {ctl.description}")
        print(f"layers combine as 1 - prod(1 - w), capped at {controls.MAX_EFFECTIVENESS}")
    elif c == "reject":
        print(f"{exceptions.reject_exception(store, args.item_id).item_id}: exception rejected")
    elif c == "change":
        from datetime import datetime
        start = datetime.fromisoformat(args.start) if args.start else None
        end = datetime.fromisoformat(args.end) if args.end else None
        item = exceptions.request_controls_change(
            store, servicenow.get_client(args.db + ".snow.json"), args.item_id, start, end, args.ci,
            args.implementation, args.backout, args.test, args.assignment_group)
        print(f"{item.item_id}: {item.exception.change_ref} raised to implement "
              f"{', '.join(item.exception.controls)}; CAB approves, a person implements, "
              f"`change sync` records it")
    elif c == "expiring":
        items = exceptions.expiring_soon(store, timedelta(days=args.days))
        print(f"{len(items)} exception(s) expiring within {args.days} days")
        for i in items:
            print(f"  {i.item_id}  {i.cve_id}  expires {i.exception_expires}  owner {i.exception.approved_by}")


def _change(store, args) -> None:
    from datetime import datetime
    client = servicenow.get_client(args.db + ".snow.json")
    c = args.ccmd
    if c == "create":
        item = store.get(args.item_id)
        if item is None:
            raise SystemExit(f"no such item: {args.item_id}")
        start, end = changes.default_window(item)
        if args.start:
            start = datetime.fromisoformat(args.start)
            end = datetime.fromisoformat(args.end) if args.end else start + timedelta(hours=4)
        req = changes.build_request(item, args.ci or [item.resource_id], start, end,
                                    args.implementation, args.backout, args.test, args.assignment_group)
        item = changes.submit_change(store, client, args.item_id, req)
        print(f"{item.item_id}: {item.refs['chg_number']} raised ({req.type}), "
              f"window {start:%Y-%m-%d %H:%M} to {end:%H:%M} UTC")
    elif c == "sync":
        r = changes.sync_changes(store, client)
        x = exceptions.sync_controls_changes(store, client)
        print(f"patch changes: approved {len(r.approved)}  declined {len(r.declined)}  errors {len(r.errors)}")
        print(f"controls changes: applied {len(x.applied)}  failed {len(x.failed)}  errors {len(x.errors)}")
        for k, v in {**r.errors, **x.errors}.items():
            print(f"  {k}: {v}")
    elif c == "gate":
        for it in store.list(State.APPROVED):
            g = changes.execution_gate(client, it)
            print(f"{it.item_id}  {it.refs.get('chg_number', '-')}  "
                  f"{'MAY PATCH ' + ','.join(g.instance_ids) if g.allowed else 'BLOCKED: ' + g.reason}")
    elif c == "patch":
        if not isinstance(client, servicenow.MockChangeClient):
            raise SystemExit("no live patch backend yet: patch only runs against the mock "
                             "(NEO_MOCK_MODE=true)")
        run = patcher.run_patch(store, client, patcher.MockPatchBackend(args.fail_at), args.item_id, args.dry_run)
        for s in run.steps:
            print(f"  {s}")
        print(f"{run.item_id}: {run.outcome}" + (f" - {run.detail}" if run.detail else ""))
    elif c == "patch-all":
        if not isinstance(client, servicenow.MockChangeClient):
            raise SystemExit("no live patch backend yet: patch only runs against the mock "
                             "(NEO_MOCK_MODE=true)")
        ids = [i.item_id for i in store.list(State.APPROVED)]
        for run in patcher.run_patch_batch(store, client, patcher.MockPatchBackend(args.fail_at), ids, args.dry_run):
            print(f"{run.item_id}: {run.outcome}" + (f" - {run.detail}" if run.detail else ""))
        if not ids:
            print("no APPROVED items")
    elif c == "close":
        r = patcher.close_verified_changes(store, client)
        print(f"changes closed: successful {len(r.successful)}  unsuccessful {len(r.unsuccessful)}  "
              f"errors {len(r.errors)}")
        for k, v in r.errors.items():
            print(f"  {k}: {v}")
    elif c == "mock-advance":
        if not isinstance(client, servicenow.MockChangeClient):
            raise SystemExit("mock-advance only works with NEO_MOCK_MODE=true")
        client.set_state(args.number, ChangeState(args.state), args.approval, args.close_code)
        print(f"{args.number} -> {args.state}" + (f" ({args.approval or args.close_code})"
                                                  if args.approval or args.close_code else ""))


def _remediate(args) -> None:
    store = SqliteStore(args.db)
    if args.rcmd == "sync":
        findings, contexts, enrichments = _load_mock(args.mock)
        # Applied exception controls stand in for the CompensatingControls tag the change writes.
        scored = score_all(findings, exceptions.overlay_contexts(store, contexts), enrichments)
        scan_id = args.scan_id or f"mock-{os.path.basename(args.mock)}"
        covered = set(contexts) or None
        # Tags as scanned, before the overlay, so drift is judged on the asset and not on Neo's credit.
        observed = {sf.finding.resource_id: controls.current_tag(contexts[sf.finding.resource_id])
                    for sf in scored if sf.finding.resource_id in contexts}
        r = sync_scan(store, scored, scan_id, window=timedelta(hours=args.window_hours),
                      covered=covered, observed_tags=observed)
        print(f"opened {len(r.opened)}  remediated {len(r.remediated)}  "
              f"reopened {len(r.reopened)}  rerouted {len(r.rerouted)}  "
              f"rescored {len(r.rescored)}  not covered by scan {len(r.not_covered)}  "
              f"tag drift {len(r.drifted)}")
        for iid in r.drifted:
            print(f"  DRIFT {iid}: {store.get(iid).exception.tag_drift} missing from the tag")
    elif args.rcmd == "advance":
        item = store.get(args.item_id)
        if item is None:
            raise SystemExit(f"no such item: {args.item_id}")
        new = State(args.state)
        try:
            item.move(new, utcnow(), refs={**item.refs, **dict(r.split("=", 1) for r in args.ref)})
        except IllegalTransition as e:
            raise SystemExit(f"illegal transition: {e}")
        store.save(item, f"advanced to {new.value}")
        print(f"{item.item_id} -> {item.state.value}")
    elif args.rcmd == "exception":
        try:
            _exception(store, args)
        except (ValueError, ChangeError) as e:   # ValueError includes IllegalTransition
            raise SystemExit(f"error: {e}")
    elif args.rcmd == "change":
        try:
            _change(store, args)
        except (ValueError, ChangeError) as e:
            raise SystemExit(f"error: {e}")
    for it in store.list():
        sla = "" if it.sla_met is None else ("  SLA met" if it.sla_met else "  SLA missed")
        esc = "  ESCALATED" if it.escalated else ""
        print(f"{it.item_id}  {it.tier}  path {it.path.value}  {it.state.value:<16} "
              f"{it.cve_id}  {it.resource_id}{sla}{esc}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="neo")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="discover → enrich → score → report")

    # Universal
    sc.add_argument("--cloud", choices=["aws", "azure", "gcp", "onprem"], default="aws")
    sc.add_argument("--mock", default=None, metavar="FILE",
                    help="path to a local findings fixture (skips live discovery)")
    sc.add_argument("--out", default="./out", metavar="DIR")
    sc.add_argument("--top", type=int, default=20)

    # AWS-specific
    sc.add_argument("--region", default="us-east-1")
    sc.add_argument("--profile", default=None)
    sc.add_argument("--source",
                    choices=["inspector", "securityhub", "nessus", "qualys", "rapid7"],
                    default=None,
                    help="discovery source (aws default: inspector; onprem: nessus)")
    sc.add_argument("--assume-role-name", default=None,
                    help="cross-account role for Org-wide EC2 exposure lookups (AWS)")

    # Azure-specific
    sc.add_argument("--subscription-id", default=None)

    # GCP-specific
    sc.add_argument("--project-id", default=None)
    sc.add_argument("--gcp-credentials", default=None, metavar="FILE",
                    help="path to GCP service account JSON key (or use GOOGLE_APPLICATION_CREDENTIALS)")

    # On-prem-specific
    sc.add_argument("--scanner-url", default=None,
                    help="base URL of the on-prem scanner (Nessus/Qualys/Rapid7)")
    sc.add_argument("--context-map", default=None, metavar="FILE",
                    help="JSON file mapping IP/hostname to exposure/criticality context")

    rm = sub.add_parser("remediate", help="track findings through the remediation lifecycle")
    rsub = rm.add_subparsers(dest="rcmd", required=True)
    rm.add_argument("--db", default="neo_remediation.db", metavar="FILE")

    rs = rsub.add_parser("sync", help="verify tracked items against a scan, then open new ones")
    rs.add_argument("--mock", required=True, metavar="FILE")
    rs.add_argument("--scan-id", default=None)
    rs.add_argument("--window-hours", type=float, default=24.0)

    rsub.add_parser("list", help="show tracked items")

    ra = rsub.add_parser("advance", help="record a human-gate or delivery step (paths A and B)")
    ra.add_argument("item_id")
    ra.add_argument("state", choices=[s.value for s in State if s is not State.EXCEPTION_ACTIVE],
                    help="exceptions are approved with `exception approve`, not advance")
    ra.add_argument("--ref", action="append", default=[], metavar="KEY=VALUE",
                    help="link to the delivery system, e.g. pr_url=... chg_number=...")

    rc = rsub.add_parser("change", help="path B: ServiceNow change for host patching")
    csub = rc.add_subparsers(dest="ccmd", required=True)
    cc = csub.add_parser("create", help="raise a change with implementation, rollback and test plans")
    cc.add_argument("item_id")
    cc.add_argument("--ci", action="append", metavar="NAME",
                    help="CMDB CI; repeat for a patch group (default: the item's own host)")
    cc.add_argument("--start", metavar="ISO8601", help="window start (default: tier-based)")
    cc.add_argument("--end", metavar="ISO8601", help="window end (default: start + 4h)")
    cc.add_argument("--implementation", default="")
    cc.add_argument("--backout", default="")
    cc.add_argument("--test", default="")
    cc.add_argument("--assignment-group", default=None)
    csub.add_parser("sync", help="pull CAB outcomes from ServiceNow into waiting items")
    csub.add_parser("gate", help="show whether each approved item may be patched right now")
    cp = csub.add_parser("patch", help="run the patch executor on an APPROVED item (mock backend only)")
    cp.add_argument("item_id")
    cp.add_argument("--dry-run", action="store_true", help="check the gate and say what would happen")
    cp.add_argument("--fail-at", choices=["snapshot", "apply", "health", "rollback"], default=None,
                    help="mock backend: simulate a failure at this step")
    ca = csub.add_parser("patch-all", help="patch every APPROVED item the gate allows, halting at the first failure")
    ca.add_argument("--dry-run", action="store_true")
    ca.add_argument("--fail-at", choices=["snapshot", "apply", "health", "rollback"], default=None)
    csub.add_parser("close", help="close changes on re-scan evidence (REMEDIATED -> successful, REOPENED -> unsuccessful)")
    cm = csub.add_parser("mock-advance", help="mock mode only: play the CAB / change manager")
    cm.add_argument("number")
    cm.add_argument("state", choices=[s.value for s in ChangeState])
    cm.add_argument("--approval", default=None, choices=["requested", "approved", "rejected"])
    cm.add_argument("--close-code", default=None, choices=["successful", "unsuccessful"],
                    help="how the implementer closed the change (with state CLOSED)")

    rx = rsub.add_parser("exception", help="path C: draft, approve and track risk exceptions")
    xsub = rx.add_subparsers(dest="ecmd", required=True)
    xd = xsub.add_parser("draft", help="submit a drafted exception for the risk owner")
    xd.add_argument("item_id")
    xd.add_argument("--control", action="append", required=True, metavar="ID",
                    help="control from the catalog; repeat for several. One of: "
                         + ", ".join(controls.CATALOG))
    xd.add_argument("--justification", default="")
    xsub.add_parser("controls", help="list the control catalog and its weights")
    xa = xsub.add_parser("approve", help="risk owner approves; expiry is capped by tier")
    xa.add_argument("item_id")
    xa.add_argument("--approver", required=True, help="named risk owner")
    xa.add_argument("--days", type=int, required=True, help="exception lifetime in days")
    xsub.add_parser("reject", help="risk owner declines").add_argument("item_id")
    xc = xsub.add_parser("change", help="after approval: raise the ServiceNow change that "
                                        "implements the controls (CAB approves, a person implements)")
    xc.add_argument("item_id")
    xc.add_argument("--ci", action="append", metavar="NAME", help="CMDB CI (default: the item's host)")
    xc.add_argument("--start", metavar="ISO8601", help="window start (default: tier-based)")
    xc.add_argument("--end", metavar="ISO8601", help="window end (default: start + 4h)")
    xc.add_argument("--implementation", default="")
    xc.add_argument("--backout", default="")
    xc.add_argument("--test", default="")
    xc.add_argument("--assignment-group", default=None)
    xe = xsub.add_parser("expiring", help="exceptions that need renewal soon")
    xe.add_argument("--days", type=int, default=7)

    args = p.parse_args(argv)

    if args.cmd == "remediate":
        return _remediate(args)

    if args.cmd == "scan":
        if args.mock:
            findings, contexts, enrichments = _load_mock(args.mock)
        else:
            live_fn = _LIVE_DISPATCH[args.cloud]
            findings, contexts, enrichments = live_fn(args)

        scored = score_all(findings, contexts, enrichments)
        os.makedirs(args.out, exist_ok=True)
        reporter.to_csv(scored,      os.path.join(args.out, "findings.csv"))
        reporter.to_json(scored,     os.path.join(args.out, "findings.json"))
        reporter.to_markdown(scored, os.path.join(args.out, "report.md"))
        print(reporter.to_console(scored, top=args.top))
        print(f"\nWrote findings.csv, findings.json, report.md to {args.out}/")


if __name__ == "__main__":
    main()
