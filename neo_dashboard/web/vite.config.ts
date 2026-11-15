import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// `npm run dev` serves the app on :5180 and forwards /api to Neo's API (uvicorn on :8790).
// Not 5173/8787: those are the Nura dashboard's ports, and a shared port would show Nura's data.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5180,
    strictPort: true,
    proxy: { "/api": "http://127.0.0.1:8790" },
  },
  // The default worker pools fail to start on this machine's Node ("reading 'config'"); vm threads work.
  test: { pool: "vmThreads" },
});
