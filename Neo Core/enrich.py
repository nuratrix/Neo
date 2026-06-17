"""Threat-intel enrichment: EPSS probability scores and CISA KEV membership."""
from __future__ import annotations

import httpx

from .models import Enrichment

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HTTP_TIMEOUT = 30.0
_EPSS_BATCH = 30  # EPSS API limit per request


def _fetch_kev() -> set[str]:
    data = httpx.get(KEV_FEED_URL, timeout=HTTP_TIMEOUT).raise_for_status().json()
    return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}


def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), _EPSS_BATCH):
        batch = cve_ids[i : i + _EPSS_BATCH]
        resp = httpx.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            for row in resp.json().get("data", []):
                scores[row["cve"].upper()] = float(row["epss"])
    return scores


def build_enrichments(cve_ids: list[str]) -> dict[str, Enrichment]:
    """Return {cve_id: Enrichment} for the given CVE list. Degrades gracefully on network error."""
    if not cve_ids:
        return {}
    unique = list({c.upper() for c in cve_ids if c})
    try:
        kev_set = _fetch_kev()
    except Exception:
        kev_set = set()
    try:
        epss_map = _fetch_epss(unique)
    except Exception:
        epss_map = {}
    return {
        cve: Enrichment(cve_id=cve, epss=epss_map.get(cve), kev=cve in kev_set)
        for cve in unique
    }
