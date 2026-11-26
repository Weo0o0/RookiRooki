import sqlite3
from pathlib import Path
from fastapi.testclient import TestClient
from backend import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

def make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("SAMPLE_EVE_PATH", str(FIXTURES_DIR / "sample_eve.json"))
    monkeypatch.setenv("PLAYBOOKS_PATH", str(FIXTURES_DIR / "playbooks.json"))
    monkeypatch.setenv("RULE_CATALOG_PATH", str(FIXTURES_DIR / "rule_catalog.json"))
    return TestClient(main.app)

def test_triage_new_fields_roundtrip_and_defaults(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    c.post("/api/ingest/sample")
    first = c.get("/api/alerts/1").json()
    assert first["analyst"] == "" and first["action_status"] == "NONE"
    assert first["verdict"] == "UNREVIEWED"
    res = c.patch("/api/alerts/1/triage", json={"analyst": "  Kim Analyst ", "action_status": "GUIDE_ONLY"})
    assert res.status_code == 200
    body = res.json()
    assert body["analyst"] == "Kim Analyst" and body["action_status"] == "GUIDE_ONLY"
    assert body["verdict"] == "UNREVIEWED" and body["observation"] == first["observation"]
    assert c.get("/api/alerts/1").json()["analyst"] == "Kim Analyst"
    # sending only other keys keeps the new fields
    kept = c.patch("/api/alerts/1/triage", json={"verdict": "TP"}).json()
    assert kept["analyst"] == "Kim Analyst" and kept["action_status"] == "GUIDE_ONLY"
    # an empty string clears the analyst
    assert c.patch("/api/alerts/1/triage", json={"analyst": ""}).json()["analyst"] == ""

def test_triage_new_fields_validation(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    c.post("/api/ingest/sample")
    assert c.patch("/api/alerts/1/triage", json={"action_status": "XXX"}).status_code == 422
    assert c.patch("/api/alerts/1/triage", json={"action_status": "isolated"}).status_code == 422
    assert c.patch("/api/alerts/1/triage", json={"analyst": "a" * (main.ANALYST_MAX_LEN + 1)}).status_code == 422
    assert c.patch("/api/alerts/1/triage", json={"analyst": "a" * main.ANALYST_MAX_LEN}).status_code == 200
    assert c.patch("/api/alerts/1/triage", json={"unknown_key": 1}).status_code == 422  # extra=forbid is kept
    assert c.patch("/api/alerts/99999/triage", json={"analyst": "x"}).status_code == 404

def test_old_db_gets_columns_idempotently(monkeypatch, tmp_path):
    db_file = tmp_path / "old.db"
    with sqlite3.connect(db_file) as db:
        db.execute(
            "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, flow_id INTEGER, sid INTEGER, "
            "category TEXT, signature TEXT, mitre_id TEXT, src_ip TEXT, dest_ip TEXT, dest_port INTEGER, http_status INTEGER, "
            "severity TEXT, is_confirmed_risk INTEGER DEFAULT 0, pii_masked INTEGER DEFAULT 0, raw_url TEXT, "
            "verdict TEXT DEFAULT 'UNREVIEWED', observation TEXT DEFAULT '', assessment TEXT DEFAULT '', confidence TEXT DEFAULT 'MEDIUM')"
        )
        db.execute("INSERT INTO alerts (timestamp, sid, category, severity, src_ip) VALUES ('t', 1000001, 'sqli', 'SEV1', '172.28.0.100')")
    c = make_client(monkeypatch, tmp_path)
    monkeypatch.setenv("DB_PATH", str(db_file))
    for _ in range(3):  # repeated init_db calls must not fail
        main.init_db()
    item = c.get("/api/alerts").json()["items"][0]
    assert item["analyst"] == "" and item["action_status"] == "NONE"
    with sqlite3.connect(db_file) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(alerts)")]
    assert cols.count("analyst") == 1 and cols.count("action_status") == 1

def test_include_fp_for_alerts_and_stats(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    c.post("/api/ingest/sample")
    all_total = c.get("/api/alerts?include_fp=1").json()["total"]
    assert all_total == c.get("/api/alerts").json()["total"] == c.get("/api/stats").json()["total"]
    sev_of_first = c.get("/api/alerts/1").json()["severity"]
    sev_total = c.get(f"/api/alerts?severity={sev_of_first}&include_fp=1").json()["total"]
    assert c.patch("/api/alerts/1/triage", json={"verdict": "FP"}).status_code == 200
    default = c.get("/api/alerts?limit=200").json()
    assert default["total"] == all_total - 1 and len(default["items"]) == all_total - 1
    assert all(i["verdict"] != "FP" for i in default["items"])
    full = c.get("/api/alerts?include_fp=1&limit=200").json()
    assert full["total"] == all_total and any(i["verdict"] == "FP" for i in full["items"])
    # the severity filter uses the same rule
    assert c.get(f"/api/alerts?severity={sev_of_first}").json()["total"] == sev_total - 1
    assert c.get(f"/api/alerts?severity={sev_of_first}&include_fp=1").json()["total"] == sev_total
    assert c.get("/api/alerts?include_fp=2").status_code == 422
    # stats use the same rule
    stats = c.get("/api/stats").json()
    assert stats["total"] == all_total - 1 and sum(stats["severity_counts"].values()) == all_total - 1
    assert sum(stats["category_counts"].values()) == all_total - 1
    stats_full = c.get("/api/stats?include_fp=1").json()
    assert stats_full["total"] == all_total and sum(stats_full["severity_counts"].values()) == all_total
    assert sum(stats_full["category_counts"].values()) == all_total
    assert c.get("/api/stats?include_fp=2").status_code == 422
