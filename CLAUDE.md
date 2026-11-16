# Project Neo

Enterprise vulnerability management platform. Scores findings by:

    risk = likelihood × impact × exposure_factor × 100

Tier cut-offs: P1 ≥ 40, P2 ≥ 20, P3 ≥ 8, P4 < 8.
A KEV finding on a public asset is always P1 regardless of arithmetic.

## Layout

```
neo_core/          neo_core Python package
  models.py        Finding, AssetContext, Enrichment, ScoredFinding
  aws_inspector.py AWS Inspector v2 discovery
  aws_securityhub.py Security Hub aggregated discovery
  aws_context.py   exposure / criticality / compensating-controls from EC2 + tags
  enrich.py        EPSS + CISA KEV threat-intel enrichment
  risk_engine.py   composite scoring engine
  reporter.py      console / CSV / JSON / Markdown output
  remediation.py   RemediationItem + state machine (PROPOSED → … → REMEDIATED / REOPENED)
  router.py        deterministic fix-type router: Path A (PR) / B (change) / C (exception)
  remediation_store.py  store interface + SQLite backend (DynamoDB later)
  closeout.py      close-out rule: findings close on re-scan evidence, not job success
  controls.py      compensating-control catalog: tag lists control IDs, code computes the weight
  exceptions.py    path C: draft / approve (named owner, tier-capped expiry) / re-route on vendor fix
  servicenow.py    change-management client: ChangeClient interface, offline mock, Table API client
  changes.py       path B: raise change (plans + CIs), pull CAB outcome, execution gate for the patcher
  patcher.py       path B executor: gate -> snapshot -> patch -> health check -> rollback; closes the change on re-scan evidence (mock backend only)
  cli.py           `neo scan` and `neo remediate` commands
  examples/mock_findings.json  demo fixture (no AWS / network needed)

neo_mcp/           MCP server wrapping the pipeline for Claude / Bedrock agents
  neo_mcp_server.py  tools (scan, Inspector, Sec Hub, GitHub PR, remediation + path-B change tools)
                     resources (kev://, epss://, scan://, remediation://)
                     prompts (triage_finding, remediation_plan, draft_change_request)
```

neo_dashboard/     read-only dashboard: items by tier P1-P4 with path A/B/C recommendation and agent suggestion (FastAPI api/ + React web/)


```bash
pip install -e ".[mcp]"
```

## Run the pipeline (mock — no AWS or network needed)

```bash
neo scan --mock "neo_core/examples/mock_findings.json" --out ./out
# or equivalently:
python -m neo_core.cli scan --mock "neo_core/examples/mock_findings.json" --out ./out
```

## Track remediation (mock — no AWS or network needed)

```bash
neo remediate --db neo.db sync --mock "neo_core/examples/mock_findings.json"   # open + route items
neo remediate --db neo.db advance REM-XXXX IN_REVIEW --ref pr_url=...          # record a gate / delivery step
neo remediate --db neo.db sync --mock "neo_core/examples/mock_rescan.json"     # verify against a re-scan
neo remediate --db neo.db list

# Path B (host patching) — mock ServiceNow state is kept in <db>.snow.json:
neo remediate --db neo.db change create REM-XXXX [--ci i-0abc --start 2026-12-01T02:00:00+00:00]
neo remediate --db neo.db change mock-advance CHG0030001 SCHEDULED --approval approved   # play the CAB
neo remediate --db neo.db change sync     # CAB approval -> item APPROVED
neo remediate --db neo.db change gate     # may the patcher run right now, and on which hosts?
neo remediate --db neo.db change patch REM-XXXX --dry-run   # then without --dry-run; --fail-at apply|health|rollback simulates failures
neo remediate --db neo.db change patch-all   # every APPROVED item the gate allows; halts at the first failure
neo remediate --db neo.db sync --mock "neo_core/examples/mock_rescan.json"   # re-scan: DEPLOYED -> REMEDIATED
neo remediate --db neo.db change close    # close changes on scan evidence (successful / unsuccessful)

# Path C (no vendor patch yet) — approval is a human gate, `advance` cannot skip it:
neo remediate --db neo.db exception controls                       # the catalog and its weights
neo remediate --db neo.db exception draft REM-XXXX --control virtual-patch --control sg-restricted
neo remediate --db neo.db exception approve REM-XXXX --approver jane.doe --days 30
neo remediate --db neo.db exception change REM-XXXX     # ServiceNow change that implements the controls
neo remediate --db neo.db change mock-advance CHG0030001 CLOSED --approval approved --close-code successful
neo remediate --db neo.db change sync                   # controls count only once that change closes successfully
neo remediate --db neo.db exception expiring --days 7
```

## Path B executor rules

The executor only touches hosts `execution_gate` returns, re-checked after the snapshot. A good
patch run leaves the item DEPLOYED, not REMEDIATED; only a re-scan closes it, and only then is the
ServiceNow change closed successful (with the scan as evidence). A failed apply/health check rolls
back, closes the change unsuccessful and sends the item back to PROPOSED (new change needed). A
failed rollback escalates, leaves the change open and blocks the item until a person clears it.
Each backend step has a time limit (900 s default): a snapshot timeout leaves the host alone, a patch
timeout stops for a person (no rollback under a running package manager), a health-check timeout rolls
back. `run_patch_batch` patches hosts one at a time and halts after the first failure (canary).
Only a mock backend exists; `execute_patch` (MCP, dry run by default) refuses outside mock mode.

## Path C flow (matches `docs/diagrams/Remediation Layer.png`)

Agent composes controls → risk owner approves (named owner, expiry capped by tier) → Neo raises a
ServiceNow change (implementation steps, rollback, CIs; P1 = emergency; window must end before the
exception expires) → CAB approves → **a person implements it manually and closes the change** (there
is no executor) → only then do the controls count → next scan reads the tag and the exposure factor
drops. A failed or cancelled change gives no credit and frees the item for a new one.
**Tag drift:** each scan compares the asset's tag with the approved controls; any missing control
flags the exception (`tag_drift`), escalates the item and withdraws the credit until the tag is back.
Assets the scan did not see are skipped. If you score with `overlay_contexts`, pass the pre-overlay
tags as `observed_tags` to `sync_scan` (the CLI does). The diagram is
generated: edit `docs/diagrams/remediation_layer.py`, then run `docs/diagrams/render.ps1`.

## Compensating-control tags

Tag (AWS/Azure `CompensatingControls`, GCP label `compensating_controls`) lists control IDs from
`neo_core/controls.py`, joined by `_`, e.g. `virtual-patch_sg-restricted`. The weights live in code,
combine as `1 - prod(1 - w)`, and are capped at 0.9. Unknown IDs earn nothing. A plain number
(`0.3`, GCP `0_3`) still works but is unverified. A new control needs a person to add it to the catalog.

## Run the dashboard

```bash
cd neo_dashboard/api && uv sync && uv run python seed_demo.py ../demo.db   # demo data (mock flow), or use your own DB
NEO_REMEDIATION_DB=../demo.db uv run uvicorn app:app --port 8790           # Nura uses 8787, so Neo does not
cd ../web && npm install && npm run dev                                    # http://localhost:5180
```

## Run the MCP server

```bash
# stdio (default, for Claude Code / Claude Desktop):
NEO_MOCK_MODE=true python "neo_mcp/neo_mcp_server.py"

# Interactive MCP Inspector:
uv run mcp dev "neo_mcp/neo_mcp_server.py"

# HTTP/SSE transport:
NEO_MCP_TRANSPORT=streamable-http python "neo_mcp/neo_mcp_server.py"
```

## Run the tests

```bash
pytest "neo_core/test_securityhub.py" "neo_core/test_remediation.py" "neo_core/test_connectors.py" "neo_core/test_servicenow.py" "neo_core/test_controls.py" "neo_core/test_patcher.py" -v
# or without pytest:
python "neo_core/test_servicenow.py"
python "neo_core/test_controls.py"
python "neo_core/test_patcher.py"
python "neo_mcp/test_remediation_tools.py"   # MCP tools; needs the mcp extra
python "neo_core/test_securityhub.py"
python "neo_core/test_remediation.py"
python "neo_core/test_connectors.py"
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NEO_MOCK_MODE` | `true` | Return synthetic data; no credentials needed |
| `NEO_MCP_TRANSPORT` | `stdio` | `stdio` \| `streamable-http` \| `sse` |
| `GITHUB_TOKEN` | — | PAT with repo scope (live PR creation only) |
| `AWS_PROFILE` / standard boto3 chain | — | Live AWS discovery |
| `NEO_REMEDIATION_DB` | `neo_remediation.db` | SQLite file for remediation items (MCP server; CLI uses `--db`) |
| `SNOW_INSTANCE_URL` / `SNOW_USERNAME` / `SNOW_PASSWORD` | — | Live ServiceNow (CMDB context + path-B changes) |
