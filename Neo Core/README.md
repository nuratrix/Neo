# Project Smith

AI-driven, environment-aware vulnerability management. This repo is the first
slice of the lifecycle on the project slide — **Discovery → Validation →
Prioritization** — built for **AWS first**, with a pluggable design so the same
engine extends to on-prem and to the later focus areas (remediation, test
automation, third-party risk, resilience).

The thesis: stop patching by raw CVSS. Patch by the **probability a vulnerability
will actually be exploited in *your* environment** — `likelihood × impact ×
exposure`, with every score fully explainable.

## Quick start

```bash
# No AWS or network needed — runs the full pipeline on a local fixture:
python -m smith.cli scan --mock examples/mock_findings.json --out ./out

# Live against AWS (needs creds + Inspector v2 enabled):
pip install -r requirements.txt
python -m smith.cli scan --region us-east-1 --profile prod --out ./out

# Organization-wide (run from the Inspector delegated-admin account; assume a
# cross-account role into members to resolve EC2 exposure):
python -m smith.cli scan --assume-role-name SmithReadOnly --out ./out

# Pull from Security Hub instead of Inspector directly:
python -m smith.cli scan --source securityhub --out ./out
```

Outputs a ranked console view plus `findings.csv`, `findings.json` (with the
per-finding score breakdown), and `report.md`.

## Why the demo result matters

In the sample run, the **xz backdoor (CVE-2024-3094, CVSS 10.0, on CISA KEV)**
scores **P4**, while a slightly lower-severity bug on a public web server scores
**P1**. Reason: xz is on an *isolated, low-criticality* batch host — high global
threat, low risk *here*. That inversion is the whole point. KEV items are always
flagged in the output, so nothing dangerous becomes invisible even when down-tiered.

## How it scores (the engine)

```
risk = likelihood  x  impact  x  exposure_factor  x  100

  likelihood       EPSS probability, floored hard by CISA KEV and by
                   Inspector's exploit-available signal
  impact           (CVSS / 10) weighted by asset business-criticality (from tags)
  exposure_factor  network exposure (public/internal/isolated), reduced by
                   compensating controls (WAF/EDR/segmentation)
```

Every `ScoredFinding` carries a `breakdown` dict, so "why is this P1?" always has
a numeric answer — essential for audits and for engineers who push back on a
deprioritized finding.

## Where the "AI" actually is

- **EPSS** is itself a machine-learning model (FIRST.org) predicting 30-day
  exploitation probability. We consume its output rather than reinventing it —
  this is the prioritization-by-probability signal.
- **Reachability analysis** (roadmap) is the next high-leverage ML/analysis layer:
  is the vulnerable code path actually loaded and callable? This typically removes
  the majority of "present but unreachable" findings.
- **LLM enrichment** (roadmap): summarize advisories and map threat-actor activity
  to your specific stack and inventory.

We deliberately keep the scoring arithmetic transparent — AI informs the inputs,
it does not become an unexplainable risk oracle.

## Architecture (pluggable by design)

```
ingest  ──►  context  ──►  enrich  ──►  score  ──►  report
(source)     (environment)  (threat-intel) (engine)   (out)

aws_inspector.py  aws_context.py  enrich.py    risk_engine.py  reporter.py
   └── swap this layer for on-prem; everything to the right is reused ──┘
```

Only the **ingest** and **context** layers are cloud-specific. `enrich`, `score`,
and `report` are infrastructure-agnostic.

**Discovery sources (no preference required — all supported):**
- `--source inspector` (default): Inspector v2 directly. From a *delegated-admin*
  account, `list_findings` already returns findings across the whole Organization.
- `--source securityhub`: pull aggregated CVE findings from Security Hub instead.
- Single-account: just run with default creds; leave `--assume-role-name` off.
- Org-wide exposure: pass `--assume-role-name <role>` and Smith assumes that
  read-only role into each member account to check public-IP + security-group
  ingress. Missing access degrades to `exposure=unknown` — it never crashes.

## Mapping to the six focus areas on the slide

| Focus area (slide)                  | Status      | Where it lives                          |
|-------------------------------------|-------------|-----------------------------------------|
| Discovery, Validation, Prioritization | **built**   | `aws_inspector` + `aws_context` + `enrich` + `risk_engine` |
| Remediation — our code              | roadmap     | `remediate/` — agent opens fix PRs into your repos |
| Remediation — third-party code      | roadmap     | `remediate/` — patch-test harness across the estate |
| Test automation                     | roadmap     | GitHub Actions workflow invoking `smith scan` as a gate |
| Third-party risk (foundational)     | roadmap     | SLA/contract tracker keyed to vendor CVE feeds |
| Resilience (foundational)           | roadmap     | EOL exposure tracking + detection/response hooks |

## On-prem extension (phase 2)

Add `ingest/nessus.py`, `ingest/qualys.py`, or `ingest/rapid7.py` that emit the
same `Finding` model, and an on-prem `context` resolver (CMDB for criticality,
firewall/segmentation data for exposure). The enrichment, scoring, and reporting
stack is unchanged — one risk model, two infrastructures, comparable scores.

## Layout

```
smith/
  models.py         source-agnostic data models
  aws_inspector.py  AWS discovery (Inspector v2)
  aws_securityhub.py AWS discovery (Security Hub aggregator)
  aws_context.py    AWS environmental context (exposure/criticality/controls; cross-account)
  enrich.py         EPSS + CISA KEV clients
  risk_engine.py    explainable composite scoring   <-- the core
  reporter.py       console / CSV / JSON / markdown
  cli.py            scan command
examples/mock_findings.json   demo fixture (no AWS/network)
tests/test_risk_engine.py
```
