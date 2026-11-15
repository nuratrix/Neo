"""Neo dashboard API: read-only. Serves the tiered overview, one item with its history, and (after
`npm run build`) the web app itself.

    uv run uvicorn app:app --port 8790          # from api/  (8787 is the Nura dashboard's port)

Configuration (.env in api/, see .env.example): NEO_REMEDIATION_DB, WINDOW_DAYS.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from source_neo import NeoSource

load_dotenv()
HERE = Path(__file__).resolve().parent
WEB_DIST = HERE.parent / "web" / "dist"
DEFAULT_DAYS = int(os.getenv("WINDOW_DAYS", "30"))

source = NeoSource(os.getenv("NEO_REMEDIATION_DB", str(HERE.parent.parent / "neo_remediation.db")))
app = FastAPI(title="Neo dashboard API", docs_url="/api/docs", openapi_url="/api/openapi.json")


@app.get("/api/meta")
def meta() -> dict:
    return {"product": "Neo", "source": source.name, "window_days": DEFAULT_DAYS, "read_only": True}


@app.get("/api/overview")
def overview(days: int = Query(DEFAULT_DAYS, ge=1, le=400)) -> dict:
    """Every item with its tier, path recommendation, latest agent suggestion and state."""
    data, errors = source.overview(days)
    return {**data, "errors": errors, "days": days}


@app.get("/api/item")
def get_item(id: str = Query(..., min_length=1)) -> dict:
    detail, errors = source.get_item(id)
    if detail is None:
        raise HTTPException(404, {"message": f"Item not found: {id}", "errors": errors})
    return {**detail, "errors": errors}


@app.get("/{path:path}", include_in_schema=False)
def web(path: str):
    """The built web app; any unknown path is a client-side route, so it gets index.html."""
    if path.startswith("api/"):
        raise HTTPException(404)
    if not WEB_DIST.is_dir():
        raise HTTPException(404, "Web app not built: run `npm run build` in web/, or use `npm run dev`.")
    file = (WEB_DIST / path).resolve()
    if path and file.is_file() and WEB_DIST.resolve() in file.parents:
        return FileResponse(file)
    return FileResponse(WEB_DIST / "index.html")
