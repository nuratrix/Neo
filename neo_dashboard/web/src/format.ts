export function relativeTime(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return iso;
  const s = Math.round((now.getTime() - then.getTime()) / 1000);
  const abs = Math.abs(s);
  if (abs < 60) return "just now";
  const text = abs < 3600 ? `${Math.floor(abs / 60)}m` : abs < 86400 ? `${Math.floor(abs / 3600)}h` : `${Math.floor(abs / 86400)}d`;
  return s >= 0 ? `${text} ago` : `in ${text}`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function day(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 10) : "—";
}

/** EXCEPTION_ACTIVE -> "Exception active". Sentences are left alone. */
export function label(code: string | null | undefined): string {
  if (code && /\s/.test(code)) return code;
  return code ? code.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase()) : "—";
}
