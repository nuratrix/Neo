import { describe, expect, it } from "vitest";
import { EMPTY, activePath, applyFilters, byTier, fromParams, toParams, toggleCell } from "./filters";
import type { ItemSummary } from "./types";

function item(over: Partial<ItemSummary>): ItemSummary {
  return {
    id: "REM-1", cve_id: "CVE-1", title: "CVE-1 in openssl", resource_id: "i-1", package: "openssl", fixed_version: "2",
    tier: "P1", tier_name: "Critical", risk_score: 90, path: "B",
    recommendation: { path: "B", path_name: "", headline: "Patch openssl", why: "", next_step: "" },
    state: "PROPOSED", needs_human: false, escalated: false, sla_due: "", sla_status: "ok",
    suggestion: null, suggestion_count: 0, has_proposal: false, updated_at: "", created_at: "", ...over,
  };
}

const items = [
  item({ id: "a", tier: "P1", path: "B" }),
  item({
    id: "b", tier: "P2", path: "A", needs_human: true, suggestion_count: 1,
    suggestion: { at: "", author: "x", kind: "fix", text: "bump spring-beans" },
  }),
  item({ id: "c", tier: "P4", path: "C", state: "REMEDIATED" }),
];

describe("filters", () => {
  it("filters by tier, path, state and the human flag", () => {
    expect(applyFilters(items, { ...EMPTY, tiers: ["P1"] }).map((i) => i.id)).toEqual(["a"]);
    expect(applyFilters(items, { ...EMPTY, paths: ["A", "C"] }).map((i) => i.id)).toEqual(["b", "c"]);
    expect(applyFilters(items, { ...EMPTY, human: true }).map((i) => i.id)).toEqual(["b"]);
    expect(applyFilters(items, { ...EMPTY, state: "REMEDIATED" }).map((i) => i.id)).toEqual(["c"]);
  });
  it("no-suggestion ignores closed items, since there is nothing left to advise on", () => {
    expect(applyFilters(items, { ...EMPTY, noSuggestion: true }).map((i) => i.id)).toEqual(["a"]);
  });
  it("searches the agent's suggestion text too", () => {
    expect(applyFilters(items, { ...EMPTY, q: "spring" }).map((i) => i.id)).toEqual(["b"]);
  });
  it("groups by tier in order, keeping empty tiers", () => {
    expect(byTier(items).map((g) => [g.tier, g.items.length])).toEqual([["P1", 1], ["P2", 1], ["P3", 0], ["P4", 1]]);
  });
  it("clicking a tier x path cell opens that tab and tier, clicking again clears only the tier", () => {
    const on = toggleCell(EMPTY, "P2", "C");
    expect(on).toMatchObject({ tiers: ["P2"], paths: ["C"] });
    expect(toggleCell(on, "P2", "C")).toMatchObject({ tiers: [], paths: ["C"] });
    expect(toggleCell({ ...on, paths: ["A"] }, "P2", "C")).toMatchObject({ tiers: ["P2"], paths: ["C"] });
  });
  it("the open tab defaults to Path A", () => {
    expect(activePath(EMPTY)).toBe("A");
    expect(activePath({ ...EMPTY, paths: ["B"] })).toBe("B");
  });
  it("round-trips through the URL and drops bad values", () => {
    const f = { ...EMPTY, q: "x", tiers: ["P1", "P3"], paths: ["C"], state: "IN_REVIEW", human: true };
    expect(fromParams(toParams(f, 30, 30))).toEqual(f);
    expect(fromParams(new URLSearchParams("tier=P9,P2&state=NOPE"))).toMatchObject({ tiers: ["P2"], state: "" });
  });
});
