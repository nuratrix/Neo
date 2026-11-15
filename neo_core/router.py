"""Deterministic remediation router -- no model involved.

    no fix at all                           -> C  (risk exception)
    dependency / image / IaC with a fix     -> A  (GitHub PR)
    host OS or installed software with fix  -> B  (ServiceNow change)

"Has a fix" means a fixed_version, or a scanner that says a patch exists
(fix_available) without naming the version -- true of several on-prem and
Azure/GCP sources. Without either there is nothing to patch to yet.
"""
from __future__ import annotations

from .models import Finding
from .remediation import PATH_A_ECOSYSTEMS, PATH_A_RESOURCE_TYPES, Path


def has_fix(f: Finding) -> bool:
    return bool(f.fixed_version) or f.fix_available


def route(f: Finding) -> Path:
    if not has_fix(f):
        return Path.C
    if f.package_ecosystem.lower() in PATH_A_ECOSYSTEMS or f.resource_type in PATH_A_RESOURCE_TYPES:
        return Path.A
    return Path.B
