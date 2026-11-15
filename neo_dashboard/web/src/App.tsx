import { useEffect, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { api } from "./api";
import ItemPage from "./pages/ItemPage";
import TierBoard from "./pages/TierBoard";
import type { Meta } from "./types";

export default function App() {
  const [meta, setMeta] = useState<Meta | null>(null);
  const [metaError, setMetaError] = useState<string | null>(null);

  useEffect(() => {
    api.meta().then(setMeta, (e: Error) => setMetaError(e.message));
  }, []);
  useEffect(() => {
    document.title = "Neo remediation";
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand-mark" aria-hidden>◆</span>
          Neo
          <span className="brand-sub">remediation by tier</span>
        </Link>
        {meta?.read_only && <span className="pill">read-only</span>}
      </header>
      {metaError && (
        <div className="banner error">
          Cannot reach the dashboard API ({metaError}). Start it from <code>api/</code> with{" "}
          <code>uv run uvicorn app:app --port 8790</code>.
        </div>
      )}
      <main>
        {meta && (
          <Routes>
            <Route path="/" element={<TierBoard meta={meta} />} />
            <Route path="/item" element={<ItemPage />} />
            <Route path="*" element={<p className="empty">Page not found. <Link to="/">All items</Link></p>} />
          </Routes>
        )}
      </main>
    </div>
  );
}
