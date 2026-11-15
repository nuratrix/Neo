"""Source-agnostic data models for the Neo pipeline."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# Scanner package-manager labels (Inspector v2 / Security Hub ASFF) -> our ecosystem.
# "OS" maps to "" because OS packages are patched on the host, not in a repo.
_ECOSYSTEM = {
    "OS": "",
    "JAR": "maven", "POM": "maven",
    "PYTHONPKG": "pypi", "PIP": "pypi", "PIPENV": "pypi", "POETRY": "pypi",
    "NODEPKG": "npm", "NPM": "npm", "YARN": "npm",
    "NUGET": "nuget",
    "GOBINARY": "golang", "GOMOD": "golang",
    "CARGO": "cargo",
    "GEMSPEC": "rubygems", "BUNDLER": "rubygems",
    "COMPOSER": "composer",
}


def ecosystem_from_package_manager(package_manager: str) -> str:
    """Map a scanner's package-manager label; unknown labels pass through lower-cased."""
    pm = (package_manager or "").upper()
    return _ECOSYSTEM[pm] if pm in _ECOSYSTEM else pm.lower()


class Finding(BaseModel):
    finding_id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: str = "UNKNOWN"
    cvss_base: float = 0.0
    resource_id: str = ""
    resource_type: str = ""
    account_id: str = ""
    region: str = ""
    package_name: str = ""
    package_ecosystem: str = ""   # maven | pypi | npm | ... | iac | image; "" = OS / installed software
    fixed_version: str = ""       # first safe version; "" = vendor has not shipped a fix
    fix_available: bool = False
    exploit_available: bool = False
    first_observed: str = ""
    cloud_provider: str = "aws"   # aws | azure | gcp | onprem


class AssetContext(BaseModel):
    resource_id: str
    exposure: str = "unknown"       # public | internal | isolated | unknown
    criticality: str = "unknown"    # critical | high | medium | low | unknown
    compensating_controls: float = 0.0
    tags: dict[str, str] = Field(default_factory=dict)


class Enrichment(BaseModel):
    cve_id: str
    epss: float | None = None
    percentile: float | None = None
    kev: bool = False
    kev_date_added: str | None = None
    kev_known_ransomware: bool = False


class ScoredFinding(BaseModel):
    finding: Finding
    context: AssetContext
    enrichment: Enrichment
    risk_score: float
    tier: str
    breakdown: dict[str, Any] = Field(default_factory=dict)
