import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Code, HumanBadge, PathBadge, SlaBadge, StateBadge, TierBadge } from "../components/Badges";
import { dateTime, day, label, relativeTime } from "../format";
import type { ItemDetail, Proposal } from "../types";

export default function ItemPage() {
  const [params] = useSearchParams();
  const id = params.get("id") ?? "";
  const [detail, setDetail] = useState<ItemDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null);
    setError(null);
    api.item(id).then(setDetail, (e: Error) => setError(e.message));
  }, [id]);

  if (error) return <div className="detail"><Link className="back" to="/">← All items</Link><div className="banner error">{error}</div></div>;
  if (!detail) return <p className="empty">Loading…</p>;

  const { summary: s, suggestions, proposal, history, evidence } = detail;
  const rec = s.recommendation;
  return (
    <div className="detail">
      <Link className="back" to="/">← All items</Link>

      <section className="detail-head">
        <div className="badges">
          <TierBadge tier={s.tier} /> <PathBadge path={s.path} title={rec.path_name} />
          <StateBadge state={s.state} /> {s.needs_human && <HumanBadge />} <SlaBadge status={s.sla_status} />
        </div>
        <h1>{s.title}</h1>
        <dl className="facts">
          <div><dt>Resource</dt><dd className="mono">{s.resource_id}</dd></div>
          <div><dt>CVE</dt><dd>{s.cve_id}</dd></div>
          <div><dt>Risk score</dt><dd>{s.risk_score.toFixed(1)} ({s.tier_name})</dd></div>
          <div><dt>Fixed version</dt><dd>{s.fixed_version || "none yet"}</dd></div>
          <div><dt>SLA due</dt><dd>{day(s.sla_due)}</dd></div>
          <div><dt>Opened</dt><dd>{dateTime(s.created_at)}</dd></div>
        </dl>
      </section>

      <div className="two-col">
        <section className="card">
          <h2>Recommended path</h2>
          <p><PathBadge path={rec.path} /> <strong>{rec.path_name}</strong></p>
          <p><strong>{rec.headline}</strong></p>
          <p className="sub">Why: {rec.why}</p>
          {rec.next_step && <p className="next">Next: {rec.next_step}</p>}
        </section>

        <section className="card">
          <h2>Agent suggestions {suggestions.length > 0 && <span className="muted">({suggestions.length}, newest first)</span>}</h2>
          {suggestions.length === 0 && <p className="muted">The agent has not recorded a suggestion for this item yet.</p>}
          <ul className="suggestions">
            {suggestions.map((g, n) => (
              <li key={n}>
                <p className="suggestion">{g.text}</p>
                <div className="sub">{label(g.kind)} · {g.author} · {dateTime(g.at)}</div>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {proposal && <ProposalCard p={proposal} />}

      <section className="card">
        <h2>History <span className="muted">({history.length} steps, newest first)</span></h2>
        <ol className="timeline">
          {history.map((h, n) => (
            <li key={n}>
              <StateBadge state={h.state} />
              <span>{label(h.event)}</span>
              <span className="sub" title={dateTime(h.at)}>{relativeTime(h.at)}</span>
            </li>
          ))}
        </ol>
      </section>

      <section className="card">
        <h2>Evidence and links</h2>
        <details>
          <summary>Show the record</summary>
          <pre>{JSON.stringify(evidence, null, 2)}</pre>
        </details>
      </section>
    </div>
  );
}

function ProposalCard({ p }: { p: Proposal }) {
  return (
    <section className="card">
      <h2>Drafted exception <span className="muted">· {label(p.status)}</span></h2>
      <dl className="kv">
        <div><dt>Controls</dt><dd>{p.controls.map((c) => <Code key={c}>{c}</Code>)} <span className="sub">reduce exposure by {(p.effectiveness * 100).toFixed(0)}%</span></dd></div>
        <div><dt>Tag to set</dt><dd><Code>{p.tag_value}</Code></dd></div>
        <div><dt>Justification</dt><dd>{p.justification || "—"}</dd></div>
        <div><dt>Approved by</dt><dd>{p.approved_by || "not yet approved"}{p.expires && ` · expires ${day(p.expires)}`}</dd></div>
        <div><dt>Controls change</dt><dd>{p.change_ref || "not raised"}{p.change_ref && (p.controls_applied ? " · implemented" : " · not implemented yet")}</dd></div>
        {p.tag_drift.length > 0 && <div><dt>Tag drift</dt><dd className="overdue">Missing from the asset's tag: {p.tag_drift.join(", ")}</dd></div>}
        {p.warnings.map((w) => <div key={w}><dt>Warning</dt><dd>{w}</dd></div>)}
      </dl>
    </section>
  );
}
