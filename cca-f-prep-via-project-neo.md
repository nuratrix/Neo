# CCA-F Prep Plan — Built on Project Neo

A 5-week study + build checklist for the **Claude Certified Architect – Foundations (CCA-F)** exam, using Project Neo (enterprise vulnerability management platform) as the working lab. Each week ships a real Neo component that also covers an exam domain, ending with timed scenario practice.

> Approach: the CCA-F is scenario-based, not a documentation quiz. Building the thing beats reading about it.

---

## Exam quick reference

- **Format:** proctored, scenario-based; 60 multiple-choice questions, 120-minute limit
- **Passing score:** scaled 720 (on a 100–1000 range)
- **Fee:** $99 USD (free for early Claude Partner Network company employees)
- **Recommended experience:** ~6 months hands-on with the Claude API and Claude Code
- **Recommended prep window:** 4–6 weeks

### Domain weights

| # | Domain | Weight |
|---|--------|--------|
| 1 | Agentic architecture & orchestration | 27% |
| 2 | Tool design & MCP integration | 18% |
| 3 | Claude Code & CI/CD integration | part of remaining ~40% |
| 4 | Prompt engineering | part of remaining ~40% |
| 5 | Context management & reliability | 15% |

### Neo coverage at a glance

| Domain | In Neo today | To build for prep |
|--------|--------------|-------------------|
| 1 — Agentic | Multi-agent vuln pipeline | Claude Agent SDK orchestration layer |
| 2 — MCP | MCP server architecture | Resources, prompts, multiple transports |
| 3 — Claude Code/CI | GitHub PR remediation flow | CLAUDE.md + Claude Code in CI |
| 4 — Prompt eng. | Structured outputs + scoring | Validation + repair loop |
| 5 — Context | Large dataset handling | Caching, compaction, evals |

---

## Prerequisites

- [ ] Confirm ~6 months Claude API + Claude Code experience (Claude Code/CI is likely the thinnest area — see Week 4)
- [ ] Register/confirm exam access (Claude Partner Network if applicable)
- [ ] Set up a clean branch in the Neo repo for prep work

---

## Week 1 — MCP foundation (Domain 2, strongest start)

Refactor Neo's MCP server to exercise all three primitives and both transports.

- [ ] Expose scanner runs (Nessus/Qualys/Rapid7), AWS Inspector + Security Hub pulls, and GitHub PR creation as **tools**
- [ ] Expose KEV/EPSS catalogs and scan results as **resources**
- [ ] Expose triage/remediation templates as **prompts**
- [ ] Implement **stdio** transport
- [ ] Implement **HTTP/SSE** transport
- [ ] Add explicit tool-level error handling
- [ ] Build one deliberately over-broad tool schema and one tightly-scoped equivalent; document why the tight one wins
- [ ] **Study:** MCP primitives, transports, tool schema design
- [ ] **Self-check:** Can you justify when a capability should be a resource vs a tool?

## Week 2 — Agentic orchestration (Domain 1, heaviest at 27%)

Re-express Neo's pipeline using the Claude Agent SDK in a hub-and-spoke pattern.

- [ ] Build an orchestrator that delegates to discovery / enrichment / scoring / remediation subagents
- [ ] Add agentic-loop control: max iterations and explicit stop conditions
- [ ] Add reliability patterns: retries and circuit breakers
- [ ] Make remediation fail safe (escalate), not fail silently
- [ ] Compare hub-and-spoke vs a flat loop on the same task; note the tradeoffs
- [ ] **Study:** subagent coordination, agentic loop design, decompose vs single-agent
- [ ] **Self-check:** Given a "broken agent loop" scenario, can you name the fix immediately?

## Week 3 — Context & reliability (Domain 5, 15% but pervasive)

Make Neo handle large finding sets efficiently and measurably.

- [ ] Add prompt caching with `cache_control` on the static scoring rubric and KEV context
- [ ] Measure and record token savings from caching
- [ ] Add compaction/summarization for hosts whose finding sets overflow the context window
- [ ] Build a small eval harness scoring risk decisions and remediation correctness vs a labeled set
- [ ] Add token estimation / budgeting for a scan-to-PR run
- [ ] **Study:** cache breakpoints, compaction patterns, eval design, token budgeting
- [ ] **Self-check:** Can you estimate token cost of a full run and point to where caching helps?

## Week 4 — Prompt engineering + Claude Code/CI (Domains 4 & 3, current divergences)

Lock down structured outputs and adopt the Claude-native CI pattern.

- [ ] Define JSON schemas for enrichment and scoring outputs
- [ ] Wrap generation in a validate → repair → retry loop
- [ ] Add a `CLAUDE.md` to the Neo repo
- [ ] Configure subagents / hooks for Claude Code
- [ ] Add a GitHub Action that runs Claude Code to triage a finding and open a remediation PR (shadow the Ansible path)
- [ ] **Study:** structured output reliability, validation loops, Claude Code config + CI patterns
- [ ] **Self-check:** What does the loop do when the model returns malformed JSON?

## Week 5 — Integration & exam readiness

- [ ] Run the full pipeline end-to-end on a real scan
- [ ] Take a timed mock exam (60 questions / 120 minutes) — rehearse pacing
- [ ] Review weakest domains from the mock
- [ ] Work through Anthropic Academy "Building with the Claude API" (Skilljar) for any gaps
- [ ] Take a second timed mock; confirm finishing inside the limit with margin
- [ ] **Self-check:** Are you completing mocks on time with room to spare?

---

## Official resources

- Anthropic Academy — "Building with the Claude API" (flagship course, 8+ hours, Skilljar)
- Claude Code course (available via Coursera / Vanderbilt)
- Official CCA-F exam guide and blueprint (Anthropic)

## Notes

- Domain 5 is only 15% but reliability/context topics surface inside other domains' scenarios — don't under-weight it.
- Spend study time roughly in proportion to domain weights; the 27% agentic domain is where most points are won or lost.
