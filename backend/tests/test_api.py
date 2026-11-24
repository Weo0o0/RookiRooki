import json
import subprocess
from fastapi.testclient import TestClient
from backend import main

def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "a.db")); monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads")); monkeypatch.setenv("SURICATA_OUT_ROOT", str(tmp_path / "out")); monkeypatch.setenv("RULES_PATH", str(tmp_path / "rules")); monkeypatch.setenv("SURICATA_BIN", "suricata-test")
    (tmp_path / "rules").write_text("rules")
    return TestClient(main.app)

def test_bad_extension_and_too_large(monkeypatch, tmp_path):
    c = client(monkeypatch, tmp_path)
    assert c.post("/api/pcap/upload", files={"file": ("x.txt", b"x")}).status_code == 400
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 2)
    response = c.post("/api/pcap/upload", files={"file": ("x.pcap", b"123")})
    assert response.status_code == 413 and not list((tmp_path / "uploads").glob("*"))

def test_upload_and_stats(monkeypatch, tmp_path):
    c = client(monkeypatch, tmp_path)
    def run(args, **kwargs):
        out = args[args.index("-l") + 1]; (tmp_path / "out" / next(iter((tmp_path / "out").iterdir())).name / "eve.json").write_text(json.dumps({"event_type":"alert","timestamp":"t","flow_id":1,"alert":{"signature_id":1000001,"signature":"ok"}}) + "\n")
        assert args == ["suricata-test", "-r", args[2], "-S", str(tmp_path / "rules"), "-l", out, "-k", "none"] and kwargs["capture_output"] and kwargs["text"]
        return subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(main.subprocess, "run", run)
    response = c.post("/api/pcap/upload", files={"file": ("x.PCAP", b"data")})
    assert response.status_code == 200 and response.json()["alerts_stored"] == 1
    assert c.get("/api/stats").json()["total"] == 1

def test_suricata_errors_are_safe(monkeypatch, tmp_path):
    c = client(monkeypatch, tmp_path)
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert c.post("/api/pcap/upload", files={"file": ("x.pcap", b"x")}).status_code == 503
