# Project Neo

Enterprise vulnerability management platform. Scores findings by:

    risk = likelihood × impact × exposure_factor × 100

Tier cut-offs: P1 ≥ 40, P2 ≥ 20, P3 ≥ 8, P4 < 8.
A KEV finding on a public asset is always P1 regardless of arithmetic.

## Layout

```
Neo Core/          neo_core Python package
  models.py        Finding, AssetContext, Enrichment, ScoredFinding
  aws_inspector.py AWS Inspector v2 discovery
  aws_securityhub.py Security Hub aggregated discovery
  aws_context.py   exposure / criticality / compensating-controls from EC2 + tags
  enrich.py        EPSS + CISA KEV threat-intel enrichment
  risk_engine.py   composite scoring engine
  reporter.py      console / CSV / JSON / Markdown output
  cli.py           `neo scan` command
  examples/mock_findings.json  demo fixture (no AWS / network needed)

Neo MCP/           MCP server wrapping the pipeline for Claude / Bedrock agents
  neo_mcp_server.py  tools (scan, Inspector, Sec Hub, GitHub PR)
                     resources (kev://, epss://, scan://)
                     prompts (triage_finding, remediation_plan)
```

## Install

```bash
pip install -e ".[mcp]"
```

## Run the pipeline (mock — no AWS or network needed)

```bash
neo scan --mock "Neo Core/examples/mock_findings.json" --out ./out
# or equivalently:
python -m neo_core.cli scan --mock "Neo Core/examples/mock_findings.json" --out ./out
```

## Run the MCP server

```bash
# stdio (default, for Claude Code / Claude Desktop):
NEO_MOCK_MODE=true python "Neo MCP/neo_mcp_server.py"

# Interactive MCP Inspector:
uv run mcp dev "Neo MCP/neo_mcp_server.py"

# HTTP/SSE transport:
NEO_MCP_TRANSPORT=streamable-http python "Neo MCP/neo_mcp_server.py"
```

## Run the tests

```bash
pytest "Neo Core/test_securityhub.py" -v
# or without pytest:
python "Neo Core/test_securityhub.py"
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NEO_MOCK_MODE` | `true` | Return synthetic data; no credentials needed |
| `NEO_MCP_TRANSPORT` | `stdio` | `stdio` \| `streamable-http` \| `sse` |
| `GITHUB_TOKEN` | — | PAT with repo scope (live PR creation only) |
| `AWS_PROFILE` / standard boto3 chain | — | Live AWS discovery |
