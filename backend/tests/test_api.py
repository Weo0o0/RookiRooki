import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.main as main_mod

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def env_setup(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    out_root = tmp_path / "suricata_out"
    db_path = tmp_path / "alerts.db"

    # Temporary test rules; the real rules/custom.rules belongs to the rule owner.
    rules_file = FIXTURES_DIR / "test_custom.rules"

    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    monkeypatch.setenv("SURICATA_OUT_ROOT", str(out_root))
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("RULES_PATH", str(rules_file))
    monkeypatch.setenv("SURICATA_BIN", "suricata-test-bin")
    monkeypatch.setenv("SURICATA_TIMEOUT", "30")

    yield {
        "upload_dir": upload_dir,
        "out_root": out_root,
        "db_path": db_path,
        "rules_file": rules_file,
    }



def test_bad_extension_returns_400(env_setup):
    client = TestClient(main_mod.app)
    resp = client.post(
        "/api/pcap/upload",
        files={"file": ("capture.txt", b"dummy data", "text/plain")},
    )
    assert resp.status_code == 400


def test_oversized_upload_returns_413_and_deletes_partial(env_setup, monkeypatch):
    monkeypatch.setattr(main_mod, "MAX_UPLOAD_BYTES", 100)
    client = TestClient(main_mod.app)
    resp = client.post(
        "/api/pcap/upload",
        files={"file": ("traffic.pcap", b"x" * 250, "application/octet-stream")},
    )
    assert resp.status_code == 413
    upload_dir = env_setup["upload_dir"]
    if upload_dir.exists():
        assert list(upload_dir.iterdir()) == []


def test_missing_rules_returns_500(env_setup, monkeypatch):
    missing_rules = env_setup["upload_dir"].parent / "no_such_rules.rules"
    monkeypatch.setenv("RULES_PATH", str(missing_rules))
    client = TestClient(main_mod.app)
    resp = client.post(
        "/api/pcap/upload",
        files={"file": ("sample.pcap", b"\xd4\xc3\xb2\xa1", "application/octet-stream")},
    )
    assert resp.status_code == 500
    assert resp.json()["detail"] == "rules/custom.rules not found"


def test_successful_upload_stores_alerts_and_updates_stats(env_setup, monkeypatch):
    captured_calls = []

    def fake_run(cmd, **kwargs):
        captured_calls.append((cmd, kwargs))
        outdir = Path(cmd[cmd.index("-l") + 1])
        eve_events = [
            json.dumps(
                {
                    "timestamp": "2026-03-01T12:00:00Z",
                    "flow_id": 10,
                    "tx_id": 0,
                    "event_type": "http",
                    "http": {
                        "url": "/items?id=1'+OR+'1'='1&token=mysecret",
                        "status": 200,
                    },
                }
            ),
            json.dumps(
                {
                    "timestamp": "2026-03-01T12:00:00Z",
                    "flow_id": 10,
                    "tx_id": 0,
                    "event_type": "alert",
                    "src_ip": "10.0.0.1",
                    "dest_ip": "10.0.0.2",
                    "dest_port": 80,
                    "alert": {"signature_id": 1000001, "signature": "SQLi Attack"},
                }
            ),
            "corrupted-json-line",
            json.dumps(
                {
                    "timestamp": "2026-03-01T12:01:00Z",
                    "flow_id": 11,
                    "event_type": "alert",
                    "src_ip": "10.0.0.3",
                    "dest_ip": "10.0.0.2",
                    "dest_port": 22,
                    "alert": {"signature_id": 1000004, "signature": "Portscan Detected"},
                }
            ),
        ]
        (outdir / "eve.json").write_text("\n".join(eve_events) + "\n", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
    client = TestClient(main_mod.app)

    resp = client.post(
        "/api/pcap/upload",
        files={"file": ("../evil_name.PCAPNG", b"pcap-bytes", "application/octet-stream")},
    )
    assert resp.status_code == 200
    body = resp.json()
    upload_id = body["upload_id"]
    assert body["alerts_stored"] == 2
    assert body["skipped_lines"] == 1
    assert body["returncode"] == 0

    assert len(captured_calls) == 1
    cmd, kwargs = captured_calls[0]
    expected_pcap_path = str(env_setup["upload_dir"] / f"{upload_id}.pcapng")
    expected_outdir = str(env_setup["out_root"] / upload_id)
    assert cmd == [
        "suricata-test-bin",
        "-r",
        expected_pcap_path,
        "-S",
        str(env_setup["rules_file"]),
        "-l",
        expected_outdir,
        "-k",
        "none",
    ]
    assert not kwargs.get("shell", False)

    stats_resp = client.get("/api/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total"] == 2
    assert stats["severity_counts"] == {"SEV1": 1, "SEV3": 1}
    assert stats["category_counts"] == {"sqli": 1, "portscan": 1}
    assert set(stats["mitre_coverage"]) == {"T1046", "T1190"}


def test_suricata_missing_returns_503(env_setup, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("suricata not found")

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
    client = TestClient(main_mod.app)
    resp = client.post(
        "/api/pcap/upload",
        files={"file": ("test.pcap", b"pcap-bytes", "application/octet-stream")},
    )
    assert resp.status_code == 503


def test_suricata_timeout_returns_504(env_setup, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
    client = TestClient(main_mod.app)
    resp = client.post(
        "/api/pcap/upload",
        files={"file": ("test.pcap", b"pcap-bytes", "application/octet-stream")},
    )
    assert resp.status_code == 504
