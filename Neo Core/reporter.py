"""Output formatters: console table, CSV, JSON, Markdown."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import ScoredFinding


def to_json(scored: list[ScoredFinding], path: str) -> None:
    Path(path).write_text(
        json.dumps([s.model_dump() for s in scored], indent=2, default=str),
        encoding="utf-8",
    )


def to_csv(scored: list[ScoredFinding], path: str) -> None:
    if not scored:
        return
    rows = [
        {
            "tier": s.tier,
            "risk_score": s.risk_score,
            "cve_id": s.finding.cve_id,
            "title": s.finding.title,
            "severity": s.finding.severity,
            "cvss_base": s.finding.cvss_base,
            "resource_id": s.finding.resource_id,
            "account_id": s.finding.account_id,
            "region": s.finding.region,
            "exposure": s.context.exposure,
            "criticality": s.context.criticality,
            "in_kev": s.enrichment.kev,
            "epss": s.enrichment.epss,
            "fix_available": s.finding.fix_available,
        }
        for s in scored
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(scored: list[ScoredFinding], path: str) -> None:
    lines = [
        "# Project Neo — Vulnerability Report",
        "",
        "| Tier | Score | CVE | Title | Resource | KEV | EPSS |",
        "|------|-------|-----|-------|----------|-----|------|",
    ]
    for s in scored:
        kev = "YES" if s.enrichment.kev else "no"
        epss = f"{s.enrichment.epss:.3f}" if s.enrichment.epss is not None else "—"
        lines.append(
            f"| {s.tier} | {s.risk_score} | {s.finding.cve_id} | {s.finding.title}"
            f" | {s.finding.resource_id} | {kev} | {epss} |"
        )
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_console(scored: list[ScoredFinding], top: int = 20) -> str:
    header = f"{'Tier':<5} {'Score':>6}  {'CVE':<18} {'Resource':<35} {'KEV':<5} Title"
    lines = [header, "-" * 100]
    for s in scored[:top]:
        kev_flag = "KEV" if s.enrichment.kev else "   "
        lines.append(
            f"{s.tier:<5} {s.risk_score:>6.1f}  {s.finding.cve_id:<18}"
            f" {s.finding.resource_id[:34]:<35} {kev_flag:<5} {s.finding.title}"
        )
    if len(scored) > top:
        lines.append(f"... and {len(scored) - top} more")
    return "\n".join(lines)
