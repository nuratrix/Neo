"""Risk scoring engine.

Implements 'shift prioritization based on the probability a vulnerability will
be exploited within OUR environment'. The score is a transparent, auditable
product of four factors -- no black box -- so any engineer (or auditor) can ask
"why is this P1?" and get a numeric answer.

    risk = likelihood  x  impact  x  exposure_factor  x  100

  likelihood       = how likely is real-world exploitation?
                     driven by EPSS (an ML model), floored hard by CISA KEV,
                     and nudged by Inspector's own exploit-available signal.
  impact           = (CVSS / 10) weighted by business criticality of the asset.
  exposure_factor  = network exposure, reduced by compensating controls.

Defaults are sensible; every weight and threshold is overridable via config.
"""
from __future__ import annotations

from .models import AssetContext, Enrichment, Finding, ScoredFinding

EXPOSURE_WEIGHT = {"public": 1.0, "internal": 0.5, "isolated": 0.2, "unknown": 0.7}
CRITICALITY_WEIGHT = {
    "critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "unknown": 0.5,
}

# KEV means it is being exploited *right now* in the wild -- never let it score low.
KEV_LIKELIHOOD_FLOOR = 0.85
# Inspector says a public exploit exists -- floor likelihood at a meaningful level.
EXPLOIT_AVAILABLE_FLOOR = 0.5

# Tier cut-offs on the 0-100 scale (overridable via config).
DEFAULT_THRESHOLDS = {"p1": 40.0, "p2": 20.0, "p3": 8.0}


def _likelihood(finding: Finding, enr: Enrichment) -> float:
    score = enr.epss or 0.0
    if finding.exploit_available:
        score = max(score, EXPLOIT_AVAILABLE_FLOOR)
    if enr.kev:
        score = max(score, KEV_LIKELIHOOD_FLOOR)
    return min(score, 1.0)


def score_finding(
    finding: Finding,
    context: AssetContext,
    enr: Enrichment,
    thresholds: dict | None = None,
) -> ScoredFinding:
    thresholds = thresholds or DEFAULT_THRESHOLDS

    likelihood = _likelihood(finding, enr)
    crit_w = CRITICALITY_WEIGHT.get(context.criticality, CRITICALITY_WEIGHT["unknown"])
    exp_w = EXPOSURE_WEIGHT.get(context.exposure, EXPOSURE_WEIGHT["unknown"])

    impact = (finding.cvss_base / 10.0) * crit_w
    exposure_factor = exp_w * (1.0 - min(max(context.compensating_controls, 0.0), 1.0))

    raw = likelihood * impact * exposure_factor
    risk = round(raw * 100.0, 1)

    # Tiering: an actively-exploited (KEV) internet-facing asset is always P1,
    # regardless of where the arithmetic lands.
    if enr.kev and context.exposure == "public":
        tier = "P1"
    elif risk >= thresholds["p1"]:
        tier = "P1"
    elif risk >= thresholds["p2"]:
        tier = "P2"
    elif risk >= thresholds["p3"]:
        tier = "P3"
    else:
        tier = "P4"

    breakdown = {
        "likelihood": round(likelihood, 4),
        "likelihood_source": (
            "CISA KEV (actively exploited)" if enr.kev
            else "Inspector exploit-available" if finding.exploit_available
            else f"EPSS {enr.epss}" if enr.epss is not None
            else "no signal"
        ),
        "impact": round(impact, 4),
        "cvss_base": finding.cvss_base,
        "criticality": context.criticality,
        "criticality_weight": crit_w,
        "exposure": context.exposure,
        "exposure_weight": exp_w,
        "compensating_controls": context.compensating_controls,
        "exposure_factor": round(exposure_factor, 4),
    }
    return ScoredFinding(
        finding=finding, context=context, enrichment=enr,
        risk_score=risk, tier=tier, breakdown=breakdown,
    )


def score_all(findings, contexts, enrichments, thresholds=None):
    """findings: list[Finding]; contexts: {resource_id: AssetContext};
    enrichments: {cve_id: Enrichment}. Returns list[ScoredFinding] sorted desc."""
    out = []
    for f in findings:
        ctx = contexts.get(f.resource_id, AssetContext(resource_id=f.resource_id))
        enr = enrichments.get(f.cve_id, Enrichment(cve_id=f.cve_id))
        out.append(score_finding(f, ctx, enr, thresholds))
    out.sort(key=lambda s: s.risk_score, reverse=True)
    return out
