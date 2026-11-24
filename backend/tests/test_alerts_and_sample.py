import json
from pathlib import Path
from fastapi.testclient import TestClient
from backend import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

EXPECTED_ALERT_KEYS = [
    "id",
    "timestamp",
    "sid",
    "category",
    "signature",
    "mitre_id",
    "src_ip",
    "dest_ip",
    "dest_port",
    "http_status",
    "severity",
    "is_confirmed_risk",
    "pii_masked",
    "raw_url",
    "verdict",
    "observation",
    "assessment",
    "confidence",
    "playbook",
]

def make_client(monkeypatch, tmp_path):
    db_file = tmp_path / "test_alerts.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("SURICATA_OUT_ROOT", str(tmp_path / "out"))
    monkeypatch.setenv("RULES_PATH", str(tmp_path / "rules"))
    monkeypatch.setenv("SAMPLE_EVE_PATH", str(FIXTURES_DIR / "sample_eve.json"))
    monkeypatch.setenv("PLAYBOOKS_PATH", str(FIXTURES_DIR / "playbooks.json"))
    monkeypatch.setenv("RULE_CATALOG_PATH", str(FIXTURES_DIR / "rule_catalog.json"))
    (tmp_path / "rules").write_text("rules")
    return TestClient(main.app)

def test_ingest_sample_and_dedupe(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    # First ingest
    res1 = c.post("/api/ingest/sample")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["alerts_stored"] == 4
    assert data1["duplicates_skipped"] == 0
    assert data1["skipped_lines"] == 0

    # Second ingest of the exact same sample -> dedupe
    res2 = c.post("/api/ingest/sample")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["alerts_stored"] == 0
    assert data2["duplicates_skipped"] == 4
    assert data2["skipped_lines"] == 0

    # Missing sample file -> 404 and detail has no absolute server path
    monkeypatch.setenv("SAMPLE_EVE_PATH", str(tmp_path / "nonexistent.json"))
    res_missing = c.post("/api/ingest/sample")
    assert res_missing.status_code == 404
    assert res_missing.json() == {"detail": "scenarios/sample_eve.json not found"}
    assert "nonexistent" not in res_missing.text
    assert str(tmp_path) not in res_missing.text

def test_reupload_dedupe_by_file_hash(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    sample_content = (FIXTURES_DIR / "sample_eve.json").read_text(encoding="utf-8")

    import subprocess
    suricata_calls = []
    def mock_run(args, **kwargs):
        suricata_calls.append(args)
        out = args[args.index("-l") + 1]
        outdir = Path(out)
        (outdir / "eve.json").write_text(sample_content, encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(main.subprocess, "run", mock_run)

    # First upload of file with bytes b"identical-pcap-data"
    res1 = c.post("/api/pcap/upload", files={"file": ("test1.pcap", b"identical-pcap-data")})
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["alerts_stored"] == 4
    assert d1["duplicates_skipped"] == 0
    assert d1["duplicate_of"] is None
    first_upload_id = d1["upload_id"]
    assert len(suricata_calls) == 1

    # Second upload of the EXACT same bytes
    res2 = c.post("/api/pcap/upload", files={"file": ("test2.pcap", b"identical-pcap-data")})
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["alerts_stored"] == 0
    assert d2["duplicates_skipped"] == 4
    assert d2["skipped_lines"] == 0
    assert d2["duplicate_of"] == first_upload_id
    # Suricata mock must NOT have been called a second time
    assert len(suricata_calls) == 1

    # DB total count must remain 4
    assert c.get("/api/stats").json()["total"] == 4

def test_reupload_dedupe_by_identity_index_different_flow_id(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)

    import subprocess
    eve_to_write = []
    def mock_run(args, **kwargs):
        out = args[args.index("-l") + 1]
        outdir = Path(out)
        content = "\n".join(json.dumps(x) for x in eve_to_write) + "\n"
        (outdir / "eve.json").write_text(content, encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(main.subprocess, "run", mock_run)

    # Run 1: alert with flow_id = 111111
    eve_to_write = [
        {"event_type": "alert", "timestamp": "2023-01-01T00:00:00Z", "flow_id": 111111, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80, "alert": {"signature_id": 1000001, "signature": "test"}}
    ]
    res1 = c.post("/api/pcap/upload", files={"file": ("run1.pcap", b"bytes-run-1")})
    assert res1.status_code == 200
    assert res1.json()["alerts_stored"] == 1

    # Run 2: DIFFERENT pcap bytes, so file hash differs. Suricata runs.
    # But eve output has the same timestamp, sid, src_ip, dest_ip, dest_port, raw_url and DIFFERENT flow_id = 999999
    eve_to_write = [
        {"event_type": "alert", "timestamp": "2023-01-01T00:00:00Z", "flow_id": 999999, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80, "alert": {"signature_id": 1000001, "signature": "test"}}
    ]
    res2 = c.post("/api/pcap/upload", files={"file": ("run2.pcap", b"bytes-run-2")})
    assert res2.status_code == 200
    assert res2.json()["alerts_stored"] == 0
    assert res2.json()["duplicates_skipped"] == 1
    assert c.get("/api/stats").json()["total"] == 1

def test_alerts_list_keys_and_pagination_and_validation(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    c.post("/api/ingest/sample")

    res = c.get("/api/alerts")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 4
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert len(body["items"]) == 4

    # Check keys order and exact match
    for item in body["items"]:
        assert list(item.keys()) == EXPECTED_ALERT_KEYS
        assert item["playbook"] is not None
        assert item["category"] in ("sqli", "xss", "bruteforce", "portscan")

    # Order newest first (id DESC)
    ids = [item["id"] for item in body["items"]]
    assert ids == sorted(ids, reverse=True)

    # Filter severity
    res_sev1 = c.get("/api/alerts?severity=SEV1")
    assert res_sev1.status_code == 200
    body_sev1 = res_sev1.json()
    assert body_sev1["total"] == 1
    assert len(body_sev1["items"]) == 1
    assert body_sev1["items"][0]["severity"] == "SEV1"

    # Pagination
    res_page = c.get("/api/alerts?limit=2&offset=1")
    assert res_page.status_code == 200
    body_page = res_page.json()
    assert body_page["total"] == 4
    assert len(body_page["items"]) == 2
    assert body_page["items"][0]["id"] == ids[1]
    assert body_page["items"][1]["id"] == ids[2]

    # Validation: invalid severity -> 422
    assert c.get("/api/alerts?severity=INVALID").status_code == 422
    assert c.get("/api/alerts?severity=sev1").status_code == 422
    # SQL injection attempt in severity
    assert c.get("/api/alerts?severity=SEV1'%20OR%201=1--").status_code == 422

    # Limit bounds 1..200
    assert c.get("/api/alerts?limit=0").status_code == 422
    assert c.get("/api/alerts?limit=201").status_code == 422
    assert c.get("/api/alerts?offset=-1").status_code == 422

def test_alert_detail(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    c.post("/api/ingest/sample")

    # Get one alert
    res = c.get("/api/alerts/1")
    assert res.status_code == 200
    item = res.json()
    assert list(item.keys()) == EXPECTED_ALERT_KEYS
    assert item["id"] == 1
    assert item["playbook"] is not None
    assert item["playbook"]["osi_layer"] == "Application"

    # Unknown id -> 404
    assert c.get("/api/alerts/99999").status_code == 404

    # Missing playbooks file -> playbook null, no 500
    monkeypatch.setenv("PLAYBOOKS_PATH", str(tmp_path / "nonexistent_playbooks.json"))
    res_no_pb = c.get("/api/alerts/1")
    assert res_no_pb.status_code == 200
    assert res_no_pb.json()["playbook"] is None

def test_alert_triage(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    c.post("/api/ingest/sample")

    # Valid triage update
    update_data = {
        "verdict": "TP",
        "confidence": "HIGH",
        "observation": "Observed attack with password=secret123 in payload",
        "assessment": "Critical attack token=xyz confirmed",
    }
    res = c.patch("/api/alerts/1/triage", json=update_data)
    assert res.status_code == 200
    updated = res.json()
    assert list(updated.keys()) == EXPECTED_ALERT_KEYS
    assert updated["verdict"] == "TP"
    assert updated["confidence"] == "HIGH"
    # Masking applied
    assert updated["observation"] == "Observed attack with password=[MASKED] in payload"
    assert updated["assessment"] == "Critical attack token=[MASKED] confirmed"

    # Partial update: update only verdict
    res2 = c.patch("/api/alerts/1/triage", json={"verdict": "FP"})
    assert res2.status_code == 200
    updated2 = res2.json()
    assert updated2["verdict"] == "FP"
    assert updated2["confidence"] == "HIGH"  # retained previous
    assert updated2["observation"] == "Observed attack with password=[MASKED] in payload"

    # Invalid verdict -> 422
    assert c.patch("/api/alerts/1/triage", json={"verdict": "NOT_AN_ENUM"}).status_code == 422
    # Invalid confidence -> 422
    assert c.patch("/api/alerts/1/triage", json={"confidence": "SUPER_HIGH"}).status_code == 422
    # Extra field forbidden -> 422
    assert c.patch("/api/alerts/1/triage", json={"extra_field": "val"}).status_code == 422
    # Empty body -> 422
    assert c.patch("/api/alerts/1/triage", json={}).status_code == 422
    # Observation > 2000 chars -> 422
    assert c.patch("/api/alerts/1/triage", json={"observation": "a" * 2001}).status_code == 422
    # Unknown id -> 404
    assert c.patch("/api/alerts/99999/triage", json={"verdict": "TP"}).status_code == 404

def test_stats_blind_rules(monkeypatch, tmp_path):
    c = make_client(monkeypatch, tmp_path)
    # Before ingest: blind_rules = []
    stats0 = c.get("/api/stats").json()
    assert stats0["blind_rules"] == []
    assert stats0["total"] == 0

    # Ingest sample (sources present: suricata_alert, suricata_http)
    c.post("/api/ingest/sample")

    stats1 = c.get("/api/stats").json()
    assert stats1["total"] == 4
    # Rule 9000001 requires ["suricata_alert", "suricata_ssh"], so suricata_ssh is missing!
    blind = stats1["blind_rules"]
    assert len(blind) == 1
    assert blind[0]["sid"] == 9000001
    assert blind[0]["category"] == "flow_anomaly"
    assert blind[0]["title"] == "Flow Anomaly"
    assert blind[0]["missing_sources"] == ["suricata_ssh"]

    # When rule catalog is missing -> blind_rules = []
    monkeypatch.setenv("RULE_CATALOG_PATH", str(tmp_path / "nonexistent_catalog.json"))
    stats_no_cat = c.get("/api/stats").json()
    assert stats_no_cat["blind_rules"] == []

    # Malformed catalog (non-dict entry, data_sources string, missing title, invalid sid) -> /api/stats 200
    bad_catalog = [
        "not a dict",
        123,
        {"sid": "not_an_int", "category": "bad", "title": "bad"},
        {"sid": 9000002, "category": "bad_sources", "data_sources": "not_a_list"},
        {"sid": 9000003, "data_sources": ["suricata_missing"]},
    ]
    bad_cat_file = tmp_path / "malformed_catalog.json"
    bad_cat_file.write_text(json.dumps(bad_catalog), encoding="utf-8")
    monkeypatch.setenv("RULE_CATALOG_PATH", str(bad_cat_file))

    res_malformed = c.get("/api/stats")
    assert res_malformed.status_code == 200
    malformed_stats = res_malformed.json()
    # 9000003 should be listed since suricata_missing is missing from latest ingest
    assert len(malformed_stats["blind_rules"]) == 1
    assert malformed_stats["blind_rules"][0]["sid"] == 9000003
    assert malformed_stats["blind_rules"][0]["category"] == ""
    assert malformed_stats["blind_rules"][0]["title"] == ""
    assert malformed_stats["blind_rules"][0]["missing_sources"] == ["suricata_missing"]
