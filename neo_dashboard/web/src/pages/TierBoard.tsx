import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { HumanBadge, PathBadge, SlaBadge, StateBadge, TierBadge } from "../components/Badges";
import { EMPTY, PATHS, STATES, TIERS, activePath, applyFilters, byTier, fromParams, toParams, toggleCell, type Filters } from "../filters";
import { day, label, relativeTime } from "../format";
import type { ItemSummary, Meta, Overview } from "../types";

const WINDOWS = [7, 30, 90, 180, 365];
const TIER_NAME: Record<string, string> = { P1: "Critical", P2: "High", P3: "Medium", P4: "Low" };
const TIER_SLA: Record<string, string> = { P1: "7 days", P2: "30 days", P3: "90 days", P4: "180 days" };
interface PathInfo {
  tab: string;
  help: string;
  brief: string;
  route: string[];
}
const PATH_INFO: Record<string, PathInfo> = {
  A: {
    tab: "Configurations",
    help: "Code & images: a pull request",
    brief:
      "Weaknesses that live in source: application dependencies, infrastructure-as-code, container images and configuration files. The fix is a code change, so it goes through your normal review and deploy pipeline.",
    route: [
      "Neo opens a pull request that bumps the dependency or corrects the configuration.",
      "A reviewer approves and merges it (In review → Approved).",
      "The pipeline deploys the change (Deployed).",
      "The next scan must no longer find the vulnerability before the item closes (Remediated).",
    ],
  },
  B: {
    tab: "Server Patches",
    help: "Hosts: a ServiceNow change and a patch",
    brief:
      "Vulnerable packages on running servers where the vendor has published a fixed version. Hosts are changed under change management, never directly.",
    route: [
      "Neo raises a ServiceNow change with the patch plan, rollback plan and affected servers (CIs).",
      "The change board (CAB) approves it and sets the maintenance window.",
      "Inside the window the patcher takes a snapshot, applies the patch and health-checks each host, one at a time; a failure rolls back and stops the run.",
      "The item is Deployed; the next scan closes it (Remediated) and Neo closes the change with the scan as evidence.",
    ],
  },
  C: {
    tab: "Compensating Controls",
    help: "No vendor fix: compensating controls and an exception",
    brief:
      "Findings with no vendor fix yet. The risk is reduced with other controls, such as a virtual patch or a restricted security group, under a time-limited, owner-approved exception.",
    route: [
      "The agent drafts the controls and the justification.",
      "A named risk owner approves the exception; its expiry is capped by the tier.",
      "Neo raises a ServiceNow change (P1 is an emergency change) and the change board approves it.",
      "A person implements the controls and closes the change. Only then do they count.",
      "The next scan reads the asset's tag and the exposure drops. If a vendor fix ships or the exception expires, the item is re-routed.",
    ],
  },
};

export default function TierBoard({ meta }: { meta: Meta }) {
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => fromParams(params), [params]);
  const days = Number(params.get("days")) || meta.window_days;

  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api
      .overview(days)
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [days]);
  useEffect(load, [load]);

  const set = (next: Filters, newDays = days) => setParams(toParams(next, newDays, meta.window_days), { replace: true });
  const update = (patch: Partial<Filters>) => set({ ...filters, ...patch });
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const allItems = data?.items ?? [];
  const tab = activePath(filters);
  const info = PATH_INFO[tab];
  const items = useMemo(() => allItems.filter((i) => i.path === tab), [allItems, tab]);
  const shown = useMemo(() => applyFilters(items, { ...filters, paths: [tab] }), [items, filters, tab]);
  const groups = useMemo(() => byTier(shown), [shown]);
  const tierCount = (t: string) => items.filter((i) => i.tier === t).length;
  const filtered = shown.length !== items.length;
  const cellOn = (t: string, p: string) => filters.tiers.length === 1 && filters.tiers[0] === t && tab === p;
  const pathCount = (p: string) => allItems.filter((i) => i.path === p).length;
  const waiting = items.filter((i) => i.needs_human).length;
  const unadvised = items.filter((i) => !i.suggestion_count && i.state !== "REMEDIATED").length;
  const overdue = items.filter((i) => i.sla_status === "overdue").length;

  return (
    <>
      <div className="tiles">
        {TIERS.map((t) => (
          <button key={t} className={`tile tile-${t.toLowerCase()} ${filters.tiers.includes(t) ? "on" : ""}`}
                  onClick={() => update({ tiers: toggle(filters.tiers, t) })}>
            <span className="tile-value">{tierCount(t)}</span>
            <span className="tile-label">{t} · {TIER_NAME[t]} · fix in {TIER_SLA[t]}</span>
          </button>
        ))}
        <button className={`tile tile-warn ${filters.human ? "on" : ""}`} onClick={() => update({ human: !filters.human })}>
          <span className="tile-value">{waiting}</span>
          <span className="tile-label">Waiting on a person</span>
        </button>
        <button className={`tile tile-muted ${filters.noSuggestion ? "on" : ""}`} onClick={() => update({ noSuggestion: !filters.noSuggestion })}>
          <span className="tile-value">{unadvised}</span>
          <span className="tile-label">No agent suggestion yet</span>
        </button>
      </div>

      {data && (
        <section className="card matrix-card" aria-label="Tier by path">
          <h2>Where the work goes <span className="muted">click a cell to filter</span></h2>
          <table className="matrix">
            <thead>
              <tr>
                <th />
                {PATHS.map((p) => (
                  <th key={p}><PathBadge path={p} /><div className="sub">{PATH_INFO[p].tab}</div></th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TIERS.map((t) => (
                <tr key={t}>
                  <th><TierBadge tier={t} /> <span className="sub">{TIER_NAME[t]}</span></th>
                  {PATHS.map((p) => {
                    const n = data.matrix[t]?.[p] ?? 0;
                    return (
                      <td key={p}>
                        <button className={`cell ${cellOn(t, p) ? "on" : ""}`} disabled={!n}
                                onClick={() => set(toggleCell(filters, t, p))}>{n}</button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <div className="toolbar">
        <input className="search" type="search" placeholder="Search CVE, package, resource, suggestion…"
               value={filters.q} onChange={(e) => update({ q: e.target.value })} />
        <label className="select">State
          <select value={filters.state} onChange={(e) => update({ state: e.target.value })}>
            <option value="">All</option>
            {STATES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
          </select>
        </label>
        <label className="select">Closed items from
          <select value={days} onChange={(e) => set(filters, Number(e.target.value))}>
            {[...new Set([...WINDOWS, meta.window_days])].sort((a, b) => a - b).map((d) => (
              <option key={d} value={d}>last {d} days</option>
            ))}
          </select>
        </label>
        <button className="button" onClick={load} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
      </div>

      {error && <div className="banner error">{error}</div>}
      {data?.errors.map((e) => <div key={e} className="banner warn">{e}</div>)}

      <div className="tabs" role="tablist" aria-label="Remediation path">
        {PATHS.map((p) => (
          <button key={p} role="tab" id={`tab-${p}`} aria-selected={tab === p} aria-controls="path-panel"
                  className={`tab ${tab === p ? "on" : ""}`}
                  onClick={() => set({ ...filters, paths: [p] })}>
            {PATH_INFO[p].tab} <span className="tab-count">{pathCount(p)}</span>
          </button>
        ))}
      </div>
      <section id="path-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="card brief">
        <h2><PathBadge path={tab} /> {info.tab} <span className="muted">· {info.help}</span></h2>
        <p>{info.brief}</p>
        <h3>Route to remediation</h3>
        <ol className="route">
          {info.route.map((s) => <li key={s}>{s}</li>)}
        </ol>
      </section>

      {data && (
        <p className="count-line">
          Showing <strong>{shown.length}</strong> of {items.length}
          {overdue > 0 && <span className="overdue"> · {overdue} past their SLA</span>}
          {filtered && <button className="link" onClick={() => set({ ...EMPTY, paths: [tab] })}>Clear filters</button>}
        </p>
      )}
      {!data && !error && <p className="empty">Loading…</p>}

      {groups.map((g) => (
        <section key={g.tier} className="tier-section">
          <h2 className="tier-head">
            <TierBadge tier={g.tier} /> {TIER_NAME[g.tier] ?? g.tier}
            <span className="muted"> · {g.items.length} {g.items.length === 1 ? "item" : "items"}{TIER_SLA[g.tier] ? ` · SLA ${TIER_SLA[g.tier]}` : ""}</span>
          </h2>
          {g.items.length === 0 ? (
            <p className="empty small">{filtered ? "Nothing in this tier matches the filters." : "Nothing open in this tier."}</p>
          ) : (
            <ul className="items">
              {g.items.map((i) => <ItemRow key={i.id} i={i} />)}
            </ul>
          )}
        </section>
      ))}
    </>
  );
}

function ItemRow({ i }: { i: ItemSummary }) {
  const rec = i.recommendation;
  return (
    <li className="item">
      <div className="item-main">
        <Link className="row-link" to={`/item?id=${encodeURIComponent(i.id)}`}>{i.title}</Link>
        <div className="sub mono">{i.resource_id}</div>
        <div className="badges">
          <span className="score" title="Risk score">{i.risk_score.toFixed(1)}</span>
          <StateBadge state={i.state} />
          {i.needs_human && <HumanBadge />}
          <SlaBadge status={i.sla_status} />
        </div>
        <div className="sub">due {day(i.sla_due)} · updated {relativeTime(i.updated_at)}</div>
      </div>
      <div className="item-col">
        <h3>Recommended path</h3>
        <div><PathBadge path={rec.path} title={rec.path_name} /> <strong>{rec.headline}</strong></div>
        <p className="sub">{rec.why}</p>
        {rec.next_step && <p className="next">Next: {rec.next_step}</p>}
      </div>
      <div className="item-col">
        <h3>Agent suggestion</h3>
        {i.suggestion ? (
          <>
            <p className="suggestion">{i.suggestion.text}</p>
            <div className="sub">{label(i.suggestion.kind)} · {relativeTime(i.suggestion.at)}
              {i.suggestion_count > 1 && ` · ${i.suggestion_count} in total`}</div>
          </>
        ) : (
          <p className="muted">{i.state === "REMEDIATED" ? "Closed." : "None recorded yet."}</p>
        )}
        {i.has_proposal && <div className="sub">Includes a drafted exception: open the item.</div>}
      </div>
    </li>
  );
}
