import ipaddress
import json
import sqlite3
import subprocess
import threading
from pathlib import Path
from fastapi.testclient import TestClient
from backend import live_capture, main

def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "a.db"))
    monkeypatch.setenv("LIVE_EVE_PATH", str(tmp_path / "eve.json"))
    monkeypatch.setattr(live_capture, "STATE", live_capture._new_state())
    main.init_db()
    return tmp_path / "eve.json"

def put(path, text, append=False):
    with open(path, "ab" if append else "wb") as f:
        f.write(text.encode())

def poll(tmp_path):
    live_capture.poll_once(tmp_path / "a.db", tmp_path / "eve.json", main.insert_alerts)

def alert(n, src="172.28.0.100", dest="172.28.0.10", sid=1000001, flow=1):
    return json.dumps({"event_type": "alert", "timestamp": f"t{n}", "flow_id": flow, "src_ip": src, "dest_ip": dest, "dest_port": 80, "tx_id": 0, "alert": {"signature_id": sid, "signature": "s"}}) + "\n"

def total(tmp_path):
    with sqlite3.connect(tmp_path / "a.db") as db:
        return db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

def spy_parse(monkeypatch):
    seen = []
    real = live_capture.parse_eve
    def spy(path):
        seen.append(Path(path).read_bytes().decode())
        return real(path)
    monkeypatch.setattr(live_capture, "parse_eve", spy)
    return seen

def test_reads_only_new_complete_lines_and_partial_waits(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    seen = spy_parse(monkeypatch)
    first, second = alert(1), alert(2)
    put(eve, first + second[:20])
    poll(tmp_path)
    assert total(tmp_path) == 1 and live_capture.STATE["offset"] == len(first)
    put(eve, second[20:], append=True)
    poll(tmp_path)
    assert total(tmp_path) == 2 and live_capture.STATE["offset"] == len(first + second)
    assert seen == [first, second] and live_capture.STATE["rows_stored"] == 2

def test_restart_does_not_reinsert(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    seen = spy_parse(monkeypatch)
    put(eve, alert(1))
    poll(tmp_path)
    monkeypatch.setattr(live_capture, "STATE", live_capture._new_state())  # restart: memory is gone
    poll(tmp_path)
    assert total(tmp_path) == 1 and len(seen) == 1 and live_capture.STATE["offset"] == len(alert(1))

def test_truncated_file_resets_offset(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    put(eve, alert(1) + alert(2))
    poll(tmp_path)
    put(eve, alert(3))
    poll(tmp_path)
    assert total(tmp_path) == 3 and live_capture.STATE["offset"] == len(alert(3))

def test_rows_outside_lab_net_are_ignored(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    put(eve, alert(1) + alert(2, src="fe80::1") + alert(3, dest="fe80::1") + alert(4, src=None) + alert(5, dest="not-an-ip"))
    poll(tmp_path)
    assert total(tmp_path) == 1
    assert live_capture.STATE["rows_stored"] == 1 and live_capture.STATE["rows_skipped_out_of_scope"] == 4

def test_http_context_from_earlier_batch_keeps_status(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    http = json.dumps({"event_type": "http", "flow_id": 1, "tx_id": 0, "http": {"status": 200, "url": "/x"}}) + "\n"
    put(eve, http)
    poll(tmp_path)
    put(eve, alert(1), append=True)
    poll(tmp_path)
    with sqlite3.connect(tmp_path / "a.db") as db:
        assert db.execute("SELECT http_status, severity FROM alerts").fetchall() == [(200, "SEV1")]

def test_flag_off_starts_nothing_and_status_reports_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "a.db"))
    for value in (None, "", "0", "true", "yes"):
        if value is None:
            monkeypatch.delenv("LIVE_CAPTURE_ENABLED", raising=False)
        else:
            monkeypatch.setenv("LIVE_CAPTURE_ENABLED", value)
        with TestClient(main.app) as c:
            body = c.get("/api/live/status").json()
            assert body["enabled"] is False and body["rows_stored"] == 0
            assert c.get("/api/stats").status_code == 200
        assert "live-capture" not in [t.name for t in threading.enumerate()]
    with sqlite3.connect(tmp_path / "a.db") as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name = 'live_capture_state'").fetchone() is None

def test_status_when_enabled_has_guidance(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.setenv("LIVE_CAPTURE_ENABLED", "1")
    body = TestClient(main.app).get("/api/live/status").json()
    assert body["enabled"] is True and body["eve_path"] == str(tmp_path / "eve.json")
    assert "-i br-minisiem" in body["start_command"] and "net 172.28.0.0/24" in body["start_command"]
    assert "pkill" in body["stop_command"]

def _sample_upload_client(monkeypatch, tmp_path):
    monkeypatch.delenv("LIVE_CAPTURE_ENABLED", raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "a.db"))
    monkeypatch.setenv("SAMPLE_EVE_PATH", str(main.ROOT / "scenarios" / "sample_eve.json"))
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("SURICATA_OUT_ROOT", str(tmp_path / "out"))
    monkeypatch.setenv("RULES_PATH", str(tmp_path / "rules"))
    (tmp_path / "rules").write_text("rules")
    return TestClient(main.app)

def _has_state_table(tmp_path):
    with sqlite3.connect(tmp_path / "a.db") as db:
        return db.execute("SELECT 1 FROM sqlite_master WHERE name = 'live_capture_state'").fetchone() is not None

def test_flag_off_sample_ingest_stores_12_alerts(monkeypatch, tmp_path):
    c = _sample_upload_client(monkeypatch, tmp_path)
    assert c.post("/api/ingest/sample").json()["alerts_stored"] == 12
    assert c.get("/api/live/status").json()["enabled"] is False
    assert not _has_state_table(tmp_path)

def test_flag_off_pcap_upload_on_empty_db_creates_no_live_table(monkeypatch, tmp_path):
    c = _sample_upload_client(monkeypatch, tmp_path)
    def run(args, **kwargs):
        out = Path(args[args.index("-l") + 1])
        (out / "eve.json").write_bytes((main.ROOT / "scenarios" / "sample_eve.json").read_bytes())
        return subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(main.subprocess, "run", run)
    body = c.post("/api/pcap/upload", files={"file": ("x.pcap", b"data")}).json()
    assert body["alerts_stored"] == 12
    assert not _has_state_table(tmp_path)

def test_same_line_appended_or_reread_creates_no_duplicates(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    put(eve, alert(1))
    poll(tmp_path)
    put(eve, alert(1), append=True)  # exact same line appended again
    poll(tmp_path)
    assert total(tmp_path) == 1
    with sqlite3.connect(tmp_path / "a.db") as db:  # offset lost: whole file is read again
        db.execute("UPDATE live_capture_state SET offset = 0")
    poll(tmp_path)
    assert total(tmp_path) == 1

def test_ipv4_outside_lab_net_only_counts_as_skipped(monkeypatch, tmp_path):
    eve = setup(monkeypatch, tmp_path)
    outside = str(ipaddress.ip_address("172.28.0.10") + 256)
    put(eve, alert(1, src=outside) + alert(2, dest=outside) + alert(3, src="::1"))
    poll(tmp_path)
    assert total(tmp_path) == 0
    assert live_capture.STATE["rows_stored"] == 0 and live_capture.STATE["rows_skipped_out_of_scope"] == 3
