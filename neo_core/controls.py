"""Compensating-control catalog: what a tag SAYS is in place -> how much exposure it removes.

Asset owners tag a resource with a list of control IDs; this module owns the weights.
That keeps the number auditable (policy, reviewed in one place) instead of self-asserted,
and lets us verify the named controls against reality later.

    CompensatingControls = "waf-managed-rules_sg-restricted"      (AWS tag / Azure tag)
    compensating_controls = "waf-managed-rules_sg-restricted"     (GCP label; '_' separates)

Controls combine as independent layers, 1 - prod(1 - w), capped at MAX_EFFECTIVENESS:
controls reduce risk, never to zero. Unknown IDs credit nothing (a typo fails safe).
A plain number ("0.3", GCP "0_3") is still honoured for existing assets but is unverified.

Weights are policy defaults -- tune them. Avoid double counting with exposure inference:
aws_context already marks an asset non-public when no security group is open to the
internet, so `sg-restricted` is only for assets that stay internet-reachable from a
known allow-list.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import AssetContext, ScoredFinding

CONTROLS_TAG_KEY = "CompensatingControls"
MAX_EFFECTIVENESS = 0.9


@dataclass(frozen=True)
class Control:
    id: str
    label: str
    weight: float
    description: str


CATALOG: dict[str, Control] = {c.id: c for c in (
    Control("feature-disabled", "Vulnerable feature disabled", 0.90,
            "The vulnerable feature/module is turned off or removed (e.g. JNDI lookups disabled)."),
    Control("virtual-patch", "Virtual patch (WAF/IPS rule for this CVE)", 0.80,
            "A WAF/IPS rule written to block this CVE's exploit pattern, in blocking mode."),
    Control("vpn-only-access", "VPN / bastion / private-link only", 0.60,
            "Service is reachable only through a VPN, bastion host or private link."),
    Control("ips-signature", "IPS signature in blocking mode", 0.50,
            "Network IPS signature covering the exploit, in blocking mode."),
    Control("sg-restricted", "Firewall / security group allow-list", 0.50,
            "Still internet-reachable, but only from a known CIDR allow-list on the affected ports."),
    Control("segmentation", "Network segmentation", 0.50,
            "Isolated segment; only the required flows are permitted in."),
    Control("waf-managed-rules", "Managed WAF ruleset", 0.40,
            "A managed WAF ruleset in blocking mode in front of the service (generic, not CVE-specific)."),
    Control("nacl-restricted", "Network ACL allow-list", 0.20,
            "Subnet NACL narrows allowed sources; stateless, so a weaker layer."),
)}

_NUMERIC = re.compile(r"^\d+(?:[._]\d+)?$")
_SPLIT = re.compile(r"[,;+_\s]+")


@dataclass
class ParsedControls:
    known: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    legacy: float | None = None      # a bare number from before the catalog existed


def parse_value(raw: str | None) -> ParsedControls:
    raw = (raw or "").strip().lower()
    if not raw:
        return ParsedControls()
    if _NUMERIC.match(raw):
        return ParsedControls(legacy=min(max(float(raw.replace("_", ".")), 0.0), 1.0))
    out = ParsedControls()
    for token in (t for t in _SPLIT.split(raw) if t):
        bucket = out.known if token in CATALOG else out.unknown
        if token not in bucket:
            bucket.append(token)
    return out


def effectiveness(ids: list[str]) -> float:
    """Combined exposure reduction (0..MAX_EFFECTIVENESS) of known controls; unknown add nothing."""
    remaining = 1.0
    for cid in set(ids):
        if cid in CATALOG:
            remaining *= 1.0 - CATALOG[cid].weight
    return round(min(1.0 - remaining, MAX_EFFECTIVENESS), 4)


def controls_from_value(raw: str | None) -> float:
    """What the context modules call: tag/label value -> compensating_controls (0..1)."""
    p = parse_value(raw)
    return p.legacy if p.legacy is not None else effectiveness(p.known)


def tag_value(ids: list[str]) -> str:
    """Canonical tag value. '_' separates because GCP labels allow only [a-z0-9_-]."""
    return "_".join(sorted(set(ids)))


def merge_tag(existing_raw: str | None, add: list[str]) -> tuple[str, list[str]]:
    """New tag value after adding controls, plus warnings about what the merge discards."""
    p = parse_value(existing_raw)
    warnings = []
    if p.legacy:
        warnings.append(f"existing numeric value {p.legacy} is unverified and will be replaced by the list")
    if p.unknown:
        warnings.append(f"existing entries not in the catalog get no credit: {', '.join(p.unknown)}")
    return tag_value(p.known + add), warnings


def tag_command(cloud: str, resource_id: str, value: str) -> str:
    """The command a human or change would run to set the tag. Informational: Neo never runs it."""
    if cloud == "azure":
        return (f'az tag update --resource-id "{resource_id}" --operation merge '
                f'--tags {CONTROLS_TAG_KEY}={value}')
    if cloud == "gcp":
        name = resource_id.rstrip("/").split("/")[-1]
        return (f"gcloud compute instances add-labels {name} --zone <ZONE> "
                f"--labels=compensating_controls={value}")
    if cloud == "onprem":
        return f'set compensating_controls = "{value}" for {resource_id} in the context map / CMDB'
    return f"aws ec2 create-tags --resources {resource_id} --tags Key={CONTROLS_TAG_KEY},Value={value}"


def project(sf: ScoredFinding, add: list[str]) -> dict:
    """What-if: the score and tier if these controls were in place. Pure; changes nothing."""
    from .risk_engine import score_finding

    unknown = [c for c in add if c not in CATALOG]
    if unknown:
        raise ValueError(f"not in the control catalog: {', '.join(unknown)}")
    cur = sf.context.compensating_controls
    combined = max(cur, min(1.0 - (1.0 - cur) * (1.0 - effectiveness(add)), MAX_EFFECTIVENESS))
    after = score_finding(sf.finding, sf.context.model_copy(update={"compensating_controls": combined}),
                          sf.enrichment)
    pinned = sf.enrichment.kev and sf.context.exposure == "public"
    return {
        "before": {"risk_score": sf.risk_score, "tier": sf.tier, "compensating_controls": cur,
                   "exposure_factor": sf.breakdown.get("exposure_factor")},
        "after": {"risk_score": after.risk_score, "tier": after.tier,
                  "compensating_controls": round(combined, 4),
                  "exposure_factor": after.breakdown.get("exposure_factor")},
        "tier_pinned": pinned,
        "note": ("Actively exploited (KEV) on a public asset: the tier stays P1 whatever the "
                 "arithmetic says, so these controls lower the score but not the tier."
                 if pinned else ""),
    }


def current_tag(ctx: AssetContext) -> str | None:
    return ctx.tags.get(CONTROLS_TAG_KEY) or ctx.tags.get("compensating_controls")
