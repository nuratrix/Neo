import { label } from "../format";

// Tones map to CSS tokens (styles.css), so the dashboard can be re-themed without touching components.
type Tone = "critical" | "high" | "medium" | "low" | "good" | "warn" | "info" | "muted";

const TIER_TONE: Record<string, Tone> = { P1: "critical", P2: "high", P3: "medium", P4: "low" };
const STATE_TONE: Record<string, Tone> = {
  REMEDIATED: "good", DEPLOYED: "info", APPROVED: "info", PROPOSED: "muted",
  IN_REVIEW: "warn", EXCEPTION_ACTIVE: "warn", REOPENED: "critical",
};
const PATH_TONE: Record<string, Tone> = { A: "info", B: "good", C: "warn" };
const SLA_TONE: Record<string, Tone> = { ok: "muted", due_soon: "warn", overdue: "critical", met: "good", missed: "critical" };
const SLA_TEXT: Record<string, string> = {
  ok: "SLA ok", due_soon: "SLA due soon", overdue: "SLA overdue", met: "SLA met", missed: "SLA missed",
};

export function Badge({ tone, children, title }: { tone: Tone; children: React.ReactNode; title?: string }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {children}
    </span>
  );
}

export const TierBadge = ({ tier }: { tier: string }) => <Badge tone={TIER_TONE[tier] ?? "muted"}>{tier}</Badge>;

export const PathBadge = ({ path, title }: { path: string; title?: string }) => (
  <Badge tone={PATH_TONE[path] ?? "muted"} title={title}>Path {path}</Badge>
);

export const StateBadge = ({ state }: { state: string }) => <Badge tone={STATE_TONE[state] ?? "info"}>{label(state)}</Badge>;

export const SlaBadge = ({ status }: { status: string }) => <Badge tone={SLA_TONE[status] ?? "muted"}>{SLA_TEXT[status] ?? status}</Badge>;

export const HumanBadge = () => <Badge tone="warn" title="A person must approve or act">Needs a human</Badge>;

export const Code = ({ children }: { children: React.ReactNode }) => <code className="code">{children}</code>;
