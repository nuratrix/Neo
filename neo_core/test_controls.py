"""Compensating-control catalog: weights come from code, not from the tag (no network)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from neo_core import aws_context, azure_context, controls, exceptions, gcp_context
from neo_core.closeout import sync_scan
from neo_core.models import AssetContext, Enrichment, Finding
from neo_core.remediation import Path
from neo_core.remediation_store import SqliteStore
from neo_core.risk_engine import score_all


def _raises(fn, exc=ValueError):
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"expected {exc.__name__}")


def test_layers_combine_as_independent_and_are_capped():
    waf, sg = controls.CATALOG["waf-managed-rules"].weight, controls.CATALOG["sg-restricted"].weight
    assert controls.effectiveness(["waf-managed-rules"]) == waf
    assert controls.effectiveness(["waf-managed-rules", "sg-restricted"]) == round(1 - (1 - waf) * (1 - sg), 4)
    assert controls.effectiveness(["waf-managed-rules", "sg-restricted"]) < waf + sg      # not additive
    assert controls.effectiveness(list(controls.CATALOG)) == controls.MAX_EFFECTIVENESS   # never zero risk


def test_duplicates_and_unknown_ids_earn_nothing():
    assert controls.effectiveness(["virtual-patch", "virtual-patch"]) == controls.effectiveness(["virtual-patch"])
    assert controls.effectiveness(["magic-box"]) == 0.0
    p = controls.parse_value("virtual-patch_magic-box")
    assert p.known == ["virtual-patch"] and p.unknown == ["magic-box"]


def test_tag_value_parsing_accepts_any_separator_and_is_case_insensitive():
    for raw in ("waf-managed-rules,sg-restricted", "WAF-Managed-Rules + sg-restricted",
                "waf-managed-rules_sg-restricted", "sg-restricted; waf-managed-rules"):
        assert sorted(controls.parse_value(raw).known) == ["sg-restricted", "waf-managed-rules"], raw
    assert controls.tag_value(["sg-restricted", "waf-managed-rules", "sg-restricted"]) == "sg-restricted_waf-managed-rules"


def test_legacy_numbers_still_work_including_gcp_decimal_encoding():
    assert controls.controls_from_value("0.3") == 0.3
    assert controls.controls_from_value("0_3") == 0.3        # GCP labels cannot hold '.'
    assert controls.controls_from_value("7") == 1.0          # clamped, as before
    assert controls.controls_from_value("") == 0.0 and controls.controls_from_value(None) == 0.0


def test_every_cloud_context_reads_the_list_form():
    value = "virtual-patch_sg-restricted"
    expected = controls.effectiveness(["virtual-patch", "sg-restricted"])
    assert aws_context._controls_from_tags({"CompensatingControls": value}) == expected
    assert azure_context._controls_from_tags({"CompensatingControls": value}) == expected
    assert gcp_context._controls_from_labels({"compensating_controls": value}) == expected
    assert aws_context._controls_from_tags({"CompensatingControls": "0.3"}) == 0.3     # legacy untouched


def test_merge_tag_keeps_existing_ids_and_warns_about_what_it_discards():
    assert controls.merge_tag("waf-managed-rules", ["sg-restricted"])[0] == "sg-restricted_waf-managed-rules"
    value, warns = controls.merge_tag("0.4", ["virtual-patch"])
    assert value == "virtual-patch" and "unverified" in warns[0]
    assert "magic-box" in controls.merge_tag("magic-box", ["virtual-patch"])[1][0]


def test_tag_commands_per_cloud():
    assert "aws ec2 create-tags --resources i-1" in controls.tag_command("aws", "i-1", "virtual-patch")
    assert "az tag update" in controls.tag_command("azure", "/subscriptions/s/vm", "virtual-patch")
    assert "compensating_controls=virtual-patch" in controls.tag_command("gcp", "//x/instances/vm1", "virtual-patch")


def _scored(exposure="internal", kev=False):
    f = Finding(cve_id="CVE-1", resource_id="i-1", package_name="p", cvss_base=9.0, resource_type="AWS_EC2_INSTANCE")
    ctx = {"i-1": AssetContext(resource_id="i-1", exposure=exposure, criticality="high",
                               tags={"CompensatingControls": "waf-managed-rules"},
                               compensating_controls=controls.effectiveness(["waf-managed-rules"]))}
    return score_all([f], ctx, {"CVE-1": Enrichment(cve_id="CVE-1", epss=0.9, kev=kev)})[0]


def test_projection_layers_on_what_is_already_in_place_and_lowers_the_score():
    sf = _scored()
    p = controls.project(sf, ["virtual-patch"])
    assert p["after"]["risk_score"] < p["before"]["risk_score"]
    assert p["after"]["compensating_controls"] > p["before"]["compensating_controls"]
    assert p["tier_pinned"] is False and p["note"] == ""
    _raises(lambda: controls.project(sf, ["magic-box"]))


def test_projection_says_when_kev_on_a_public_asset_pins_the_tier():
    p = controls.project(_scored(exposure="public", kev=True), ["feature-disabled", "virtual-patch"])
    assert p["after"]["tier"] == "P1" and p["tier_pinned"] is True and "stays P1" in p["note"]
    assert p["after"]["risk_score"] < p["before"]["risk_score"]


def test_exception_stores_computed_weight_and_tag_and_rejects_uncatalogued_controls():
    s = SqliteStore(":memory:")
    f = Finding(cve_id="CVE-1", resource_id="i-1", package_name="p", cvss_base=9.0)
    sync_scan(s, score_all([f], {}, {}), "scan-1")
    item = s.list()[0]
    assert item.path is Path.C
    _raises(lambda: exceptions.draft_exception(s, item.item_id, ["home-made-firewall"]))
    out = exceptions.draft_exception(s, item.item_id, ["sg-restricted", "waf-managed-rules"])
    assert out.exception.controls_effectiveness == controls.effectiveness(["sg-restricted", "waf-managed-rules"])
    assert out.exception.tag_value == "sg-restricted_waf-managed-rules"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all control tests passed")
