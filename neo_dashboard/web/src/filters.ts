import type { ItemSummary } from "./types";

export const TIERS = ["P1", "P2", "P3", "P4"] as const;
export const PATHS = ["A", "B", "C"] as const;
export const STATES = ["PROPOSED", "IN_REVIEW", "APPROVED", "DEPLOYED", "EXCEPTION_ACTIVE", "REMEDIATED", "REOPENED"] as const;

export interface Filters {
  q: string;
  tiers: string[];
  paths: string[];
  state: string;
  human: boolean; // only items waiting on a person
  noSuggestion: boolean; // only items the agent has not advised on yet
}

export const EMPTY: Filters = { q: "", tiers: [], paths: [], state: "", human: false, noSuggestion: false };

export function applyFilters(items: ItemSummary[], f: Filters): ItemSummary[] {
  const q = f.q.trim().toLowerCase();
  return items.filter(
    (i) =>
      (!f.tiers.length || f.tiers.includes(i.tier)) &&
      (!f.paths.length || f.paths.includes(i.path)) &&
      (!f.state || i.state === f.state) &&
      (!f.human || i.needs_human) &&
      (!f.noSuggestion || (!i.suggestion_count && i.state !== "REMEDIATED")) &&
      (!q ||
        [i.title, i.cve_id, i.resource_id, i.package, i.recommendation.headline, i.suggestion?.text].some((v) =>
          v?.toLowerCase().includes(q),
        )),
  );
}

/** Items grouped by tier, in tier order, each group already ordered by the API (highest risk first). */
export function byTier(items: ItemSummary[]): { tier: string; items: ItemSummary[] }[] {
  const known = TIERS.map((tier) => ({ tier: tier as string, items: items.filter((i) => i.tier === tier) }));
  const other = items.filter((i) => !(TIERS as readonly string[]).includes(i.tier));
  return [...known, ...(other.length ? [{ tier: "other", items: other }] : [])];
}

/** The path tab that is open: the first selected path, else Path A. */
export function activePath(f: Filters): string {
  return f.paths[0] ?? PATHS[0];
}

/** Click a tier/path cell: open that path's tab and show only that tier; clicking again clears the tier (the tab stays). */
export function toggleCell(f: Filters, tier: string, path: string): Filters {
  const on = f.tiers.length === 1 && f.tiers[0] === tier && activePath(f) === path;
  return { ...f, tiers: on ? [] : [tier], paths: [path] };
}

export function toParams(f: Filters, days: number, defaultDays: number): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q) p.set("q", f.q);
  if (f.tiers.length) p.set("tier", f.tiers.join(","));
  if (f.paths.length) p.set("path", f.paths.join(","));
  if (f.state) p.set("state", f.state);
  if (f.human) p.set("human", "1");
  if (f.noSuggestion) p.set("nosug", "1");
  if (days !== defaultDays) p.set("days", String(days));
  return p;
}

export function fromParams(p: URLSearchParams): Filters {
  const list = (k: string, allowed: readonly string[]) => (p.get(k)?.split(",") ?? []).filter((v) => allowed.includes(v));
  const state = p.get("state") ?? "";
  return {
    q: p.get("q") ?? "",
    tiers: list("tier", TIERS),
    paths: list("path", PATHS),
    state: (STATES as readonly string[]).includes(state) ? state : "",
    human: p.get("human") === "1",
    noSuggestion: p.get("nosug") === "1",
  };
}
