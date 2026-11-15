import type { ItemDetail, Meta, Overview } from "./types";

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function getJson<T>(path: string, params: Record<string, string | number> = {}): Promise<T> {
  const query = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]));
  const url = query.size ? `${path}?${query}` : path;
  const resp = await fetch(url, { headers: { Accept: "application/json" } });
  if (!resp.ok) {
    let message = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      message = body?.detail?.message ?? body?.detail ?? message;
    } catch {
      /* not JSON: keep the status line */
    }
    throw new ApiError(String(message), resp.status);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  meta: () => getJson<Meta>("/api/meta"),
  overview: (days: number) => getJson<Overview>("/api/overview", { days }),
  item: (id: string) => getJson<ItemDetail>("/api/item", { id }),
};
