# neo_dashboard

A read-only web dashboard for Neo's remediation work, organised the way you triage it: **by tier (P1–P4)**, and for each item the **path Neo recommends (A, B or C)** and the **agent's suggestion**.

```
web/  (React + TypeScript, Vite)  ──/api──▶  api/  (FastAPI)  ──▶  Neo's remediation database (SQLite, opened read-only)
```

It started from the Nura findings dashboard (same stack and look), but the pages, API and data model are Neo's own. It does not share ports, code paths or data with Nura.

## What you see

**Board (home page)**
- **Tier tiles:** P1 Critical, P2 High, P3 Medium, P4 Low, with the SLA for each tier, plus *waiting on a person* and *no agent suggestion yet*. Click a tile to filter.
- **Tier × path grid:** how many items of each tier go down Path A (code & images → pull request), Path B (host patch → ServiceNow change) and Path C (no vendor fix → compensating controls + exception). Click a cell to filter.
- **One section per tier,** highest risk first. Each item shows three columns:
  1. the finding: CVE, package, resource, risk score, state, SLA, whether a person must act;
  2. **Recommended path:** the path Neo's router chose, what to do, why, and the next step;
  3. **Agent suggestion:** the latest advice the agent recorded, or "None recorded yet".
- Filters: search (includes suggestion text), path, state, waiting on a person, no suggestion. They live in the URL, so a view can be bookmarked.

**Item page:** the recommended path with its reasoning; every agent suggestion, newest first; for Path C the exception the agent drafted (controls, tag to set, justification, approver, expiry, the controls change and whether a person has implemented it, tag drift); the full history; and the raw evidence and links (PR, ServiceNow change).

## Where the agent suggestions come from

The agent records advice with the MCP tool `record_agent_suggestion(item_id, text, kind)`. It is advisory text only: it changes no state and approves nothing. Until the agent calls it, the board says "None recorded yet", and the *no agent suggestion yet* tile counts those items. The Path C draft (controls and justification) comes from `draft_risk_exception` and shows on the item page.

The recommended path is not agent output. It is Neo's deterministic router (`neo_core/router.py`), shown with its reason.

## Quick start

You need [uv](https://docs.astral.sh/uv/) and Node.js 20+.

```powershell
cd neo_dashboard/api
uv sync
uv run python seed_demo.py ../demo.db           # demo data: drives Neo's mock scan, ServiceNow and patcher
$env:NEO_REMEDIATION_DB = "../demo.db"; uv run uvicorn app:app --port 8790
```
In a second terminal:
```powershell
cd neo_dashboard/web
npm install
npm run dev            # http://localhost:5180
```

**Ports.** Neo uses **8790** (API) and **5180** (dev server), and `web/vite.config.ts` pins both. The Nura dashboard uses 8787 and 5173/5174; if the proxy pointed at 8787 you would see Nura's data in this UI.

**Your own data:** point `NEO_REMEDIATION_DB` at the file `neo remediate --db <file>` writes, or at the MCP server's database (default `neo_remediation.db` in the repo root). `api/.env.example` lists the settings.

## Populating the dashboard with mock data

No AWS, ServiceNow or network access is needed. There are two ways.

**Option 1: the seed script (recommended).** It drives Neo's mock scan, mock ServiceNow and patcher to build a complete demo database:

```powershell
cd neo_dashboard/api
uv sync
uv run python seed_demo.py ../demo.db
$env:NEO_REMEDIATION_DB = "../demo.db"; uv run uvicorn app:app --port 8790
```

It creates:
- open items across P1–P4 and Paths A, B and C (from both mock fixtures);
- one closed item: a P1 host patched, confirmed by a re-scan, its change closed;
- one change waiting for the change board, and one Path C exception approved but waiting for a person to implement the controls change;
- demo agent suggestions on the P1–P3 items, and none on P4, so you can see both states.

It writes `demo.db` and `demo.db.snow.json` (both gitignored). Delete them and run the script again for a clean start.

**Option 2: the CLI.** From the repo root:

```powershell
neo remediate --db neo.db sync --mock "neo_core/examples/mock_findings.json"
$env:NEO_REMEDIATION_DB = "neo.db"
```

This gives you items and routing only: no agent suggestions, no closed item, no pending changes. Add suggestions through the MCP tool `record_agent_suggestion`, and use the other `neo remediate` commands (see the repo's CLAUDE.md) to move items through changes and re-scans.

The dashboard is read-only and never creates a database: if `NEO_REMEDIATION_DB` points at a missing file, it shows a "no remediation database" banner.

**Single process:** `npm run build` in `web/`; the API then serves the built app at its own port.

## Read-only, by construction

The database is opened with SQLite `mode=ro` and the API only has GET endpoints, so the dashboard cannot change a remediation, approve a change or advance an item. It never creates the database file. Approvals stay in ServiceNow, with the risk owner, and in the CLI/MCP tools.

## API

| Endpoint | Returns |
|---|---|
| `GET /api/meta` | `product`, `source`, `window_days`, `read_only` |
| `GET /api/overview?days=30` | `items` (tier-ordered, each with its recommendation, latest suggestion, state, SLA), `matrix` (tier × path counts), `needs_human`, `no_suggestion`, `overdue`, `errors` |
| `GET /api/item?id=REM-…` | `summary`, `suggestions`, `proposal` (Path C draft), `history`, `evidence` |

`days` hides closed items older than that; open items always show. OpenAPI docs: `/api/docs`.

## Tests

```powershell
cd api; uv run pytest        # tiers, matrix, recommendations, suggestions, read-only, window, errors, API
cd web; npm test             # filters, URL state, formatting
cd web; npm run build        # typecheck + production build
```

## Not built yet

- **Authentication.** The API has none and is meant to run on your machine. Put it behind an identity provider before hosting it.
- **Acting on items** (approve, patch). Read-only on purpose.
- **Live refresh and trends.** The board re-reads on load and on Refresh; SLA over time and tier burn-down are not charted yet.
- **Stored agent suggestions are only as good as the agent's calls.** Nothing prompts the agent to record one; add that to its workflow (for example at the end of the `triage_finding` and `remediation_plan` prompts) if you want every item covered.
