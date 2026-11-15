# Diagram sources

`Neo — Remediation Layer.png` (page 3 of 3) is generated, not drawn by hand. Edit the content in
[remediation_layer.py](remediation_layer.py), then re-render:

```powershell
powershell -File docs/diagrams/render.ps1 -Font path\to\inter.woff2
```

- Output is 1800×1680, written to the repo root. `-Out` writes elsewhere, `-Python` picks the interpreter.
- `-Font` is optional. The diagrams use Inter; without it the system font is used and text widths
  shift slightly. Inter is on Google Fonts (`Inter:wght@400..700`, the `latin` woff2).
- Needs Edge or Chrome. The script renders taller than the page and crops, because a headless
  window reserves space for browser chrome and would otherwise clip the bottom.

Each Path C box in the script matches code: `exceptions.py` (draft, approve, change, sync) and the
MCP tools in `neo_mcp/neo_mcp_server.py`. Change one, change the other.

Pages 1 and 2 (`Neo — Deterministic Scoring.png`, `Neo — Judgment Layer.png`) are still plain images.
