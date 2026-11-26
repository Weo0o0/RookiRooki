import json
import sqlite3
import subprocess
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import isolation, main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
NET = "mini-siem-net"
JST = timezone(timedelta(hours=9))


def ts(seconds_ago=0):
    # Same shape as Suricata output: microseconds and a +HHMM offset.
    return (datetime.now(JST) - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


class FakeDocker:
    def __init__(self, connected=True, running=True, ip="172.28.0.100"):
        self.connected, self.running, self.ip = connected, running, ip
        self.calls, self.kwargs = [], []
        self.fail = None  # (returncode, stderr) tuple or an exception instance

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        self.kwargs.append(kwargs)
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail:
            return subprocess.CompletedProcess(args, self.fail[0], "", self.fail[1])
        if args[1] == "inspect":
            nets = {NET: {"IPAddress": self.ip}} if self.connected else {}
            body = [{"State": {"Running": self.running}, "NetworkSettings": {"Networks": nets}}]
            return subprocess.CompletedProcess(args, 0, json.dumps(body), "")
        if args[1:3] == ["network", "disconnect"]:
            self.connected = False
        elif args[1:3] == ["network", "connect"]:
            self.connected = True
        return subprocess.CompletedProcess(args, 0, "", "")

    def mutating(self):
        return [c for c in self.calls if c[1] == "network"]


@pytest.fixture
def env(monkeypatch, tmp_path):
    db_file = tmp_path / "iso.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setenv("PLAYBOOKS_PATH", str(FIXTURES_DIR / "playbooks.json"))
    monkeypatch.setenv("ISOLATION_ENABLED", "1")
    monkeypatch.setenv("DOCKER_BIN", "docker-test")
    isolation.reset_tokens()
    fake = FakeDocker()
    monkeypatch.setattr(isolation.subprocess, "run", fake)
    client = TestClient(main.app)
    main.init_db()
    counter = [0]

    def add_alert(severity="SEV1", src_ip="172.28.0.100", age=5):
        counter[0] += 1
        with closing(sqlite3.connect(db_file)) as db:
            cur = db.execute(
                "INSERT INTO alerts (timestamp, sid, category, severity, src_ip, dest_ip, dest_port, raw_url) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ts(age), 1000001, "sqli", severity, src_ip, "172.28.0.10", 80, f"/x?{counter[0]}"),
            )
            db.commit()
            return cur.lastrowid

    return client, fake, add_alert, db_file


def token_of(client, alert_id):
    return client.get(f"/api/alerts/{alert_id}").json()["isolation_token"]


def test_token_only_when_eligible(env, monkeypatch):
    client, fake, add, _ = env
    ok = add()
    first = token_of(client, ok)
    assert isinstance(first, str) and len(first) >= 32
    assert token_of(client, ok) == first
    assert token_of(client, add(severity="SEV2")) is None
    assert token_of(client, add(severity="SEV3")) is None
    assert token_of(client, add(src_ip="172.28.0.10")) is None
    assert token_of(client, add(src_ip="172.28.0.50")) is None
    assert token_of(client, add(age=301)) is None
    assert token_of(client, add(age=-120)) is None
    listed = client.get("/api/alerts?limit=200").json()["items"]
    assert sum(1 for item in listed if item["isolation_token"]) == 1
    assert fake.calls == []  # issuing tokens on GET never touches docker
    monkeypatch.setenv("ISOLATION_ENABLED", "0")
    assert token_of(client, ok) is None


def test_unparseable_timestamp_gives_no_token(env):
    client, _, add, db_file = env
    alert_id = add()
    with closing(sqlite3.connect(db_file)) as db:
        db.execute("UPDATE alerts SET timestamp = 'garbage' WHERE id = ?", (alert_id,))
        db.commit()
    assert token_of(client, alert_id) is None


def test_isolate_uses_fixed_commands_and_token_is_single_use(env):
    client, fake, add, db_file = env
    alert_id = add()
    token = token_of(client, alert_id)
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert res.status_code == 200
    assert res.json() == {"status": "isolated", "ip": "172.28.0.100", "container": "attacker"}
    assert fake.calls[0] == ["docker-test", "inspect", "--type", "container", "attacker"]
    assert fake.mutating() == [["docker-test", "network", "disconnect", NET, "attacker"]]
    for kw in fake.kwargs:
        assert kw.get("shell") is False
        assert kw.get("timeout") == isolation.DOCKER_TIMEOUT_SECONDS
        assert kw.get("stdin") == subprocess.DEVNULL
    again = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert again.status_code == 403 and again.json()["detail"] == "Token already used"
    assert token_of(client, alert_id) is None
    with closing(sqlite3.connect(db_file)) as db:
        rows = db.execute(
            "SELECT alert_id, ip, container, action, result, detail FROM isolation_log ORDER BY id"
        ).fetchall()
        dump = json.dumps(db.execute("SELECT * FROM isolation_log").fetchall())
    assert rows[0] == (alert_id, "172.28.0.100", "attacker", "isolate", "ok", "isolated")
    assert rows[1][3:5] == ("isolate", "fail")
    assert token not in dump


def test_rejections_never_call_docker(env, monkeypatch):
    client, fake, add, _ = env
    alert_id = add()
    token = token_of(client, alert_id)
    assert client.post("/api/isolate", json={"alert_id": alert_id, "token": "wrong"}).status_code == 403
    assert client.post("/api/isolate", json={"alert_id": alert_id, "token": "\u00e9" * 5}).status_code == 403
    assert client.post("/api/isolate", json={"alert_id": 99999, "token": token}).status_code == 404
    assert client.post("/api/isolate", json={"alert_id": alert_id}).status_code == 422
    assert client.post("/api/isolate", json={"alert_id": alert_id, "token": token, "ip": "1.1.1.1"}).status_code == 422
    for ip in ("172.28.0.11", "172.28.0.1", "10.0.0.5"):
        other = add(src_ip=ip)
        res = client.post("/api/isolate", json={"alert_id": other, "token": token})
        assert res.status_code == 403 and res.json()["detail"] == "Target not allowed"
    assert fake.calls == []
    real_now = isolation.now
    later = timedelta(seconds=isolation.TOKEN_TTL_SECONDS + 1)
    monkeypatch.setattr(isolation, "now", lambda: real_now() + later)
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert res.status_code == 403 and res.json()["detail"] == "Token expired"
    assert fake.calls == []


def test_disabled_never_calls_docker(env, monkeypatch):
    client, fake, add, _ = env
    alert_id = add()
    token = token_of(client, alert_id)
    monkeypatch.delenv("ISOLATION_ENABLED")
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert res.status_code == 403 and "disabled" in res.json()["detail"].lower()
    res = client.post("/api/unisolate", json={"alert_id": alert_id})
    assert res.status_code == 403 and "disabled" in res.json()["detail"].lower()
    assert token_of(client, alert_id) is None
    assert client.get("/api/alerts").status_code == 200
    assert client.get("/api/isolation/status").status_code == 200
    assert fake.calls == []


def test_isolate_is_idempotent_when_already_disconnected(env):
    client, fake, add, _ = env
    fake.connected = False
    alert_id = add()
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token_of(client, alert_id)})
    assert res.status_code == 200 and res.json()["status"] == "already_isolated"
    assert fake.mutating() == []


def test_unisolate_restores_ip_and_is_idempotent(env):
    client, fake, add, _ = env
    fake.connected = False
    alert_id = add()
    res = client.post("/api/unisolate", json={"alert_id": alert_id})
    assert res.status_code == 200 and res.json()["status"] == "unisolated"
    expected = ["docker-test", "network", "connect", "--ip", "172.28.0.100", NET, "attacker"]
    assert fake.mutating() == [expected]
    again = client.post("/api/unisolate", json={"ip": "172.28.0.100"})
    assert again.status_code == 200 and again.json()["status"] == "already_connected"
    assert len(fake.mutating()) == 1
    assert client.post("/api/unisolate", json={"ip": "172.28.0.10"}).status_code == 403
    assert client.post("/api/unisolate", json={"ip": "172.28.0.100; rm -rf /"}).status_code == 403
    assert client.post("/api/unisolate", json={}).status_code == 422
    assert client.post("/api/unisolate", json={"alert_id": alert_id, "ip": "172.28.0.100"}).status_code == 422
    assert client.post("/api/unisolate", json={"alert_id": 99999}).status_code == 404
    assert len(fake.mutating()) == 1


def test_unisolate_fails_when_ip_not_kept(env, monkeypatch):
    client, fake, _, _ = env
    fake.connected = False

    def wrong_ip(args, **kwargs):
        result = fake(args, **kwargs)
        if args[1:3] == ["network", "connect"]:
            fake.ip = "172.28.0.77"
        return result

    monkeypatch.setattr(isolation.subprocess, "run", wrong_ip)
    res = client.post("/api/unisolate", json={"ip": "172.28.0.100"})
    assert res.status_code == 502 and res.json()["detail"] == "IP not restored"


@pytest.mark.parametrize(
    "fail,code,detail",
    [
        (FileNotFoundError(), 503, "Docker unavailable"),
        (subprocess.TimeoutExpired("docker", 10), 504, "Docker timed out"),
        (
            (1, "permission denied while trying to connect to the Docker daemon socket at /var/run/docker.sock"),
            503,
            "Docker permission denied",
        ),
        ((1, "Error response from daemon: No such container: attacker"), 404, "Target container not found"),
        ((1, "boom /etc/secret/path"), 502, "Docker command failed"),
    ],
)
def test_docker_failures_are_safe_and_keep_token(env, fail, code, detail):
    client, fake, add, db_file = env
    alert_id = add()
    token = token_of(client, alert_id)
    fake.fail = fail
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert res.status_code == code and res.json() == {"detail": detail}
    assert "/etc" not in res.text and "boom" not in res.text and "docker.sock" not in res.text
    fake.fail = None
    assert client.post("/api/isolate", json={"alert_id": alert_id, "token": token}).status_code == 200
    with closing(sqlite3.connect(db_file)) as db:
        assert db.execute("SELECT result FROM isolation_log ORDER BY id").fetchall()[0] == ("fail",)


def test_unexpected_docker_output_is_bad_gateway(env, monkeypatch):
    client, _, add, _ = env
    alert_id = add()
    token = token_of(client, alert_id)

    def garbage(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "not json", "")

    monkeypatch.setattr(isolation.subprocess, "run", garbage)
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert res.status_code == 502 and res.json() == {"detail": "Unexpected docker output"}


def test_isolation_not_confirmed_is_bad_gateway(env, monkeypatch):
    client, fake, add, _ = env
    alert_id = add()
    token = token_of(client, alert_id)

    def stays_connected(args, **kwargs):
        if args[1:3] == ["network", "disconnect"]:
            fake.calls.append(list(args))
            return subprocess.CompletedProcess(args, 0, "", "")
        return fake(args, **kwargs)

    monkeypatch.setattr(isolation.subprocess, "run", stays_connected)
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token})
    assert res.status_code == 502 and res.json() == {"detail": "Isolation not confirmed"}
    monkeypatch.setattr(isolation.subprocess, "run", fake)
    fake.connected = True
    assert client.post("/api/isolate", json={"alert_id": alert_id, "token": token}).status_code == 200


def test_stopped_container_is_conflict(env):
    client, fake, add, _ = env
    fake.running = False
    alert_id = add()
    res = client.post("/api/isolate", json={"alert_id": alert_id, "token": token_of(client, alert_id)})
    assert res.status_code == 409 and res.json()["detail"] == "Target container is not running"
    assert fake.mutating() == []


def test_concurrent_same_token_isolates_once(env):
    client, fake, add, db_file = env
    alert_id = add()
    token = token_of(client, alert_id)
    results = []

    def worker():
        with closing(sqlite3.connect(db_file)) as db:
            db.row_factory = sqlite3.Row
            try:
                results.append(("ok", isolation.isolate(db, alert_id, token)["status"]))
            except isolation.IsolationError as exc:
                results.append(("err", exc.detail))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r[0] for r in results) == ["err"] * 7 + ["ok"]
    assert all(r[1] == "Token already used" for r in results if r[0] == "err")
    assert len(fake.mutating()) == 1


def test_status_prefers_docker_then_falls_back_to_log(env, monkeypatch):
    client, fake, add, _ = env
    alert_id = add()
    client.post("/api/isolate", json={"alert_id": alert_id, "token": token_of(client, alert_id)})
    body = client.get("/api/isolation/status").json()
    assert body["enabled"] is True and body["allowed_ips"] == ["172.28.0.100"]
    assert body["isolated_ips"] == ["172.28.0.100"] and body["source"] == "docker"
    assert body["recent"][0]["action"] == "isolate" and body["recent"][0]["result"] == "ok"
    fake.connected = True  # restored by hand: docker state wins over the log
    assert client.get("/api/isolation/status").json()["isolated_ips"] == []
    fake.fail = FileNotFoundError()
    fallback = client.get("/api/isolation/status").json()
    assert fallback["source"] == "log" and fallback["isolated_ips"] == ["172.28.0.100"]
    assert fallback["docker_error"] == "Docker unavailable"
    monkeypatch.delenv("ISOLATION_ENABLED")
    fake.calls.clear()
    off = client.get("/api/isolation/status").json()
    assert off["enabled"] is False and off["source"] == "log" and fake.calls == []
