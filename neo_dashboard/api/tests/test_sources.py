"""Neo source and API: tiers, path recommendations, agent suggestions, read-only, window, errors."""
import importlib
import json
import shutil
import sqlite3

import pytest

from seed_demo import seed
from source_neo import NeoSource


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    path = tmp_path_factory.mktemp("neo") / "demo.db"
    seed(path)
    return path


def overview(db, days=30):
    data, errors = NeoSource(db).overview(days)
    assert not errors
    return data


def test_every_tier_and_path_is_present_and_ordered_by_tier_then_risk(db):
    data = overview(db)
    items = data["items"]
    assert {i["tier"] for i in items} == {"P1", "P2", "P3", "P4"}
    assert {i["path"] for i in items} == {"A", "B", "C"}
    tiers = [i["tier"] for i in items]
    assert tiers == sorted(tiers)
    for t in ("P1", "P2", "P3", "P4"):
        scores = [i["risk_score"] for i in items if i["tier"] == t]
        assert scores == sorted(scores, reverse=True)


def test_matrix_counts_match_the_items(db):
    data = overview(db)
    for t, row in data["matrix"].items():
        for p, n in row.items():
            assert n == sum(1 for i in data["items"] if i["tier"] == t and i["path"] == p)
    assert sum(sum(r.values()) for r in data["matrix"].values()) == len(data["items"])


def test_each_item_carries_the_router_recommendation_with_a_reason(db):
    for i in overview(db)["items"]:
        r = i["recommendation"]
        assert r["path"] == i["path"] and r["headline"] and r["why"] and r["path_name"]
    by_path = {i["path"]: i["recommendation"] for i in overview(db)["items"]}
    assert "pull request" in by_path["A"]["path_name"]
    assert "no fix yet" in by_path["C"]["why"].lower() or "no fix" in by_path["C"]["why"].lower()


def test_agent_suggestions_show_when_recorded_and_not_otherwise(db):
    items = overview(db)["items"]
    p1 = [i for i in items if i["tier"] == "P1" and i["state"] != "REMEDIATED"]
    assert p1 and all(i["suggestion"] and i["suggestion"]["text"] for i in p1)
    p4 = [i for i in items if i["tier"] == "P4" and i["state"] != "REMEDIATED"]
    assert p4 and all(i["suggestion"] is None and i["suggestion_count"] == 0 for i in p4)
    assert overview(db)["no_suggestion"] == len([i for i in items if not i["suggestion_count"] and i["state"] != "REMEDIATED"])


def test_needs_human_and_sla_flags(db):
    items = overview(db)["items"]
    waiting = [i for i in items if i["state"] == "IN_REVIEW"]
    assert waiting and all(i["needs_human"] for i in waiting)
    closed = [i for i in items if i["state"] == "REMEDIATED"]
    assert closed and all(i["sla_status"] in ("met", "missed") and not i["needs_human"] for i in closed)


def test_item_detail_has_suggestions_newest_first_history_and_the_drafted_exception(db):
    data = overview(db)
    c = next(i for i in data["items"] if i["state"] == "EXCEPTION_ACTIVE")
    detail, errors = NeoSource(db).get_item(c["id"])
    assert not errors and detail["proposal"]["controls"] == ["sg-restricted", "virtual-patch"]
    assert detail["proposal"]["approved_by"] == "demo.risk.owner" and detail["proposal"]["change_ref"].startswith("CHG")
    assert detail["history"][0]["state"] == "EXCEPTION_ACTIVE" and detail["history"][-1]["state"] == "PROPOSED"
    done = next(i for i in data["items"] if i["state"] == "REMEDIATED")
    d2, _ = NeoSource(db).get_item(done["id"])
    states = [h["state"] for h in d2["history"]]
    assert states[0] == "REMEDIATED" and "DEPLOYED" in states and d2["proposal"] is None


def test_unknown_item_and_missing_database_are_not_exceptions(db, tmp_path):
    assert NeoSource(db).get_item("REM-NOPE")[0] is None
    data, errors = NeoSource(tmp_path / "absent.db").overview(30)
    assert data["items"] == [] and "no remediation database" in errors[0]
    assert not (tmp_path / "absent.db").exists()                  # read-only: never creates the file


def test_the_database_is_opened_read_only(db):
    ro = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM items")


def test_old_closed_items_leave_the_window_but_open_ones_stay(db, tmp_path):
    copy = tmp_path / "old.db"
    shutil.copy(db, copy)
    con = sqlite3.connect(copy)
    for iid, body in con.execute("SELECT item_id, body FROM items").fetchall():
        d = json.loads(body)
        if d["state"] == "REMEDIATED":
            d["remediated_at"] = "2020-01-01T00:00:00+00:00"
            con.execute("UPDATE items SET body=? WHERE item_id=?", (json.dumps(d), iid))
    con.commit(); con.close()
    after = overview(copy)["items"]
    assert len(after) == len(overview(db)["items"]) - 1 and all(i["state"] != "REMEDIATED" for i in after)


def test_corrupt_database_is_reported(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_text("not sqlite")
    data, errors = NeoSource(bad).overview(30)
    assert data["items"] == [] and errors


def test_api_endpoints(db, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("NEO_REMEDIATION_DB", str(db))
    import app as app_module
    c = TestClient(importlib.reload(app_module).app)
    assert c.get("/api/meta").json() == {"product": "Neo", "source": "neo", "window_days": 30, "read_only": True}
    data = c.get("/api/overview").json()
    assert data["items"] and data["matrix"] and data["errors"] == []
    one = c.get("/api/item", params={"id": data["items"][0]["id"]}).json()
    assert one["summary"]["id"] == data["items"][0]["id"] and one["history"]
    assert c.get("/api/item", params={"id": "REM-NOPE"}).status_code == 404
    assert c.post("/api/overview").status_code in (404, 405)       # nothing writes
