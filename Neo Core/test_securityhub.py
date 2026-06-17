"""Test that Security Hub ASFF findings normalize correctly to our Finding model."""
import os
import sys

# Add the Neo/ root so that `neo_core` (mapped from "Neo Core/" via pyproject.toml)
# resolves correctly when running the test directly without `pip install -e .`.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from neo_core.aws_securityhub import normalize_asff  # installed package
except ModuleNotFoundError:
    from aws_securityhub import normalize_asff  # fallback: run from inside Neo Core/

SAMPLE = {
    "Id": "arn:aws:securityhub:us-east-1:111111111111:finding/abc",
    "Title": "CVE-2021-44228 - log4j-core",
    "AwsAccountId": "111111111111",
    "Severity": {"Label": "CRITICAL"},
    "Resources": [{"Id": "i-0public-web-01", "Type": "AwsEc2Instance", "Region": "us-east-1"}],
    "Vulnerabilities": [
        {"Id": "CVE-2021-44228", "Cvss": [{"BaseScore": 10.0, "Version": "3.1"}],
         "FixAvailable": "YES", "ExploitAvailable": "YES",
         "VulnerablePackages": [{"Name": "log4j-core"}]},
        {"Id": "CVE-2021-45046", "Cvss": [{"BaseScore": 9.0}],
         "FixAvailable": "YES", "VulnerablePackages": [{"Name": "log4j-core"}]},
    ],
}


def test_one_finding_per_cve():
    out = normalize_asff(SAMPLE)
    assert len(out) == 2
    assert {f.cve_id for f in out} == {"CVE-2021-44228", "CVE-2021-45046"}


def test_type_mapped_to_canonical():
    out = normalize_asff(SAMPLE)
    assert all(f.resource_type == "AWS_EC2_INSTANCE" for f in out)


def test_fields_extracted():
    f = normalize_asff(SAMPLE)[0]
    assert f.cvss_base == 10.0
    assert f.fix_available and f.exploit_available
    assert f.account_id == "111111111111"
    assert f.resource_id == "i-0public-web-01"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all securityhub tests passed")
