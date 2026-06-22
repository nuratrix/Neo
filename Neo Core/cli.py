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
  neo scan --cloud aws --mock "Neo Core/examples/mock_findings.json" --out ./out
"""
from __future__ import annotations

import argparse
import json
import os

from . import reporter
from .models import AssetContext, Enrichment, Finding
from .risk_engine import score_all


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

    args = p.parse_args(argv)

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
