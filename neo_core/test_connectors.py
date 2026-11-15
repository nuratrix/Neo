"""Connectors must carry fix data through to the router (no AWS or network needed)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from neo_core.aws_inspector import normalize_finding
from neo_core.aws_securityhub import normalize_asff
from neo_core.models import ecosystem_from_package_manager
from neo_core.remediation import Path
from neo_core.router import route


def _inspector(pkg: dict, rtype="AWS_EC2_INSTANCE", fix="YES") -> dict:
    return {
        "findingArn": "arn:f1", "title": "t", "severity": "HIGH", "awsAccountId": "1",
        "fixAvailable": fix, "resources": [{"id": "r-1", "type": rtype, "region": "us-east-1"}],
        "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-1", "vulnerablePackages": [pkg]},
    }


def _asff(pkg: dict, rtype="AwsEc2Instance") -> dict:
    return {
        "Id": "arn:f1", "Severity": {"Label": "HIGH"}, "AwsAccountId": "1",
        "Resources": [{"Id": "r-1", "Type": rtype, "Region": "us-east-1"}],
        "Vulnerabilities": [{"Id": "CVE-1", "FixAvailable": "YES", "VulnerablePackages": [pkg]}],
    }


def test_ecosystem_mapping():
    assert ecosystem_from_package_manager("OS") == ""
    assert ecosystem_from_package_manager("jar") == "maven"
    assert ecosystem_from_package_manager("PYTHONPKG") == "pypi"
    assert ecosystem_from_package_manager("NODEPKG") == "npm"
    assert ecosystem_from_package_manager("SOMETHINGNEW") == "somethingnew"
    assert ecosystem_from_package_manager("") == ""


def test_inspector_os_package_on_host_routes_to_b():
    f = normalize_finding(_inspector({"name": "openssl", "packageManager": "OS", "fixedInVersion": "3.0.9"}))
    assert (f.fixed_version, f.package_ecosystem) == ("3.0.9", "")
    assert route(f) is Path.B


def test_inspector_library_routes_to_a():
    f = normalize_finding(_inspector({"name": "log4j-core", "packageManager": "JAR", "fixedInVersion": "2.17.1"}))
    assert f.package_ecosystem == "maven" and route(f) is Path.A


def test_inspector_container_image_routes_to_a_even_for_os_package():
    f = normalize_finding(_inspector({"name": "zlib", "packageManager": "OS", "fixedInVersion": "1.2.13"},
                                     rtype="AWS_ECR_CONTAINER_IMAGE"))
    assert route(f) is Path.A


def test_inspector_no_fix_routes_to_c():
    f = normalize_finding(_inspector({"name": "pkg", "packageManager": "OS"}, fix="NO"))
    assert f.fixed_version == "" and route(f) is Path.C


def test_securityhub_carries_fixed_version_and_ecosystem():
    f = normalize_asff(_asff({"Name": "requests", "PackageManager": "PYTHONPKG", "FixedInVersion": "2.31.0"}))[0]
    assert (f.fixed_version, f.package_ecosystem) == ("2.31.0", "pypi")
    assert route(f) is Path.A


def test_scanner_that_only_says_fix_exists_still_routes_to_b_not_c():
    from neo_core.models import Finding
    f = Finding(cve_id="CVE-1", resource_id="h-1", resource_type="host", fix_available=True)
    assert f.fixed_version == "" and route(f) is Path.B


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all connector tests passed")
