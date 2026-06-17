"""Project Smith CLI.

  python -m smith.cli scan --region us-east-1 --profile prod --out ./out
  python -m smith.cli scan --mock examples/mock_findings.json --out ./out

The --mock path runs the full enrich/score/report pipeline against a local
fixture with no AWS or network access -- useful for demos, tests, and CI.
"""
from __future__ import annotations

import argparse
import json
import os

from . import reporter
from .models import AssetContext, Enrichment, Finding
from .risk_engine import score_all


def _load_mock(path: str):
    with open(path) as fh:
        data = json.load(fh)
    findings = [Finding(**f) for f in data["findings"]]
    contexts = {c["resource_id"]: AssetContext(**c) for c in data.get("contexts", [])}
    enrichments = {e["cve_id"]: Enrichment(**e) for e in data.get("enrichments", [])}
    return findings, contexts, enrichments


def _live(region, profile, source, assume_role_name):
    from . import aws_context, enrich
    if source == "securityhub":
        from . import aws_securityhub as ingest
    else:
        from . import aws_inspector as ingest
    findings = ingest.pull_findings(region=region, profile=profile)
    contexts = aws_context.build_contexts(
        findings, region=region, profile=profile, assume_role_name=assume_role_name
    )
    enrichments = enrich.build_enrichments([f.cve_id for f in findings if f.cve_id])
    return findings, contexts, enrichments


def main(argv=None):
    p = argparse.ArgumentParser(prog="smith")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="discover, enrich, score, report")
    sc.add_argument("--region", default="us-east-1")
    sc.add_argument("--profile", default=None)
    sc.add_argument("--source", choices=["inspector", "securityhub"], default="inspector",
                    help="discovery source (Inspector v2 direct, or Security Hub aggregator)")
    sc.add_argument("--assume-role-name", default=None,
                    help="cross-account role for Organization-wide exposure lookups")
    sc.add_argument("--mock", default=None, help="path to a local findings fixture")
    sc.add_argument("--out", default="./out", help="output directory")
    sc.add_argument("--top", type=int, default=20)
    args = p.parse_args(argv)

    if args.cmd == "scan":
        if args.mock:
            findings, contexts, enrichments = _load_mock(args.mock)
        else:
            findings, contexts, enrichments = _live(
                args.region, args.profile, args.source, args.assume_role_name
            )

        scored = score_all(findings, contexts, enrichments)
        os.makedirs(args.out, exist_ok=True)
        reporter.to_csv(scored, os.path.join(args.out, "findings.csv"))
        reporter.to_json(scored, os.path.join(args.out, "findings.json"))
        reporter.to_markdown(scored, os.path.join(args.out, "report.md"))
        print(reporter.to_console(scored, top=args.top))
        print(f"\nWrote findings.csv, findings.json, report.md to {args.out}/")


if __name__ == "__main__":
    main()
