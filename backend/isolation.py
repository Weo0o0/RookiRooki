import hmac
import json
import logging
import os
import secrets
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# Hard-coded lab target: only the attacker container on the lab network.
ISOLATION_NETWORK = "mini-siem-net"
ISOLATION_TARGETS = {"172.28.0.100": "attacker"}
ELIGIBLE_SEVERITY = "SEV1"
TOKEN_TTL_SECONDS = 600
ALERT_MAX_AGE_SECONDS = 300
CLOCK_SKEW_SECONDS = 60
DOCKER_TIMEOUT_SECONDS = 10
RECENT_LOG_LIMIT = 20
TIMESTAMP_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")

ISOLATION_LOG_DDL = (
    "CREATE TABLE IF NOT EXISTS isolation_log ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "alert_id INTEGER, "
    "ip TEXT, "
    "container TEXT, "
    "action TEXT NOT NULL, "
    "result TEXT NOT NULL, "
    "detail TEXT, "
    "created_at TEXT NOT NULL)"
)

# Lock order is always _DOCKER_LOCK first, then _TOKEN_LOCK.
_TOKEN_LOCK = threading.Lock()
_DOCKER_LOCK = threading.Lock()
_TOKENS: Dict[int, Dict[str, Any]] = {}


class IsolationError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def enabled() -> bool:
    return os.getenv("ISOLATION_ENABLED") == "1"


def docker_bin() -> str:
    return os.getenv("DOCKER_BIN", "docker")


def now() -> datetime:
    return datetime.now(timezone.utc)


def parse_alert_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo is not None else None
    return None


def is_eligible(row, at: Optional[datetime] = None) -> bool:
    if not enabled():
        return False
    if row["severity"] != ELIGIBLE_SEVERITY or row["src_ip"] not in ISOLATION_TARGETS:
        return False
    created = parse_alert_time(row["timestamp"])
    if created is None:
        return False
    age = ((at or now()) - created).total_seconds()
    return -CLOCK_SKEW_SECONDS <= age <= ALERT_MAX_AGE_SECONDS


def issue_token(row) -> Optional[str]:
    if not is_eligible(row):
        return None
    current = now()
    with _TOKEN_LOCK:
        grace = timedelta(seconds=TOKEN_TTL_SECONDS)
        for key in [k for k, v in _TOKENS.items() if current > v["expires_at"] + grace]:
            del _TOKENS[key]
        entry = _TOKENS.get(row["id"])
        if entry is None:
            entry = {
                "token": secrets.token_urlsafe(32),
                "expires_at": current + grace,
                "used": False,
            }
            _TOKENS[row["id"]] = entry
        if entry["used"] or current >= entry["expires_at"]:
            return None
        return entry["token"]


def _check_token(alert_id: int, supplied: str) -> None:
    with _TOKEN_LOCK:
        entry = _TOKENS.get(alert_id)
        if entry is None or not hmac.compare_digest(entry["token"].encode("utf-8"), supplied.encode("utf-8")):
            raise IsolationError(403, "Invalid token")
        if entry["used"]:
            raise IsolationError(403, "Token already used")
        if now() >= entry["expires_at"]:
            raise IsolationError(403, "Token expired")


def _consume_token(alert_id: int) -> None:
    with _TOKEN_LOCK:
        _TOKENS[alert_id]["used"] = True


def reset_tokens() -> None:
    with _TOKEN_LOCK:
        _TOKENS.clear()


def _run_docker(args: List[str]):
    # args are always fixed lists built from the constants above; never request text.
    try:
        result = subprocess.run(
            [docker_bin(), *args],
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise IsolationError(503, "Docker unavailable")
    except subprocess.TimeoutExpired:
        raise IsolationError(504, "Docker timed out")
    if result.returncode != 0:
        stderr = (result.stderr or "")[:500]
        logging.error("docker %s failed (%s): %s", args[0], result.returncode, stderr)
        lowered = stderr.lower()
        if "permission denied" in lowered:
            raise IsolationError(503, "Docker permission denied")
        if "no such container" in lowered:
            raise IsolationError(404, "Target container not found")
        raise IsolationError(502, "Docker command failed")
    return result


def inspect_target(container: str) -> Dict[str, Any]:
    result = _run_docker(["inspect", "--type", "container", container])
    try:
        data = json.loads(result.stdout)[0]
        running = bool(data["State"]["Running"])
        networks = data["NetworkSettings"]["Networks"] or {}
        endpoint = networks.get(ISOLATION_NETWORK) or {}
        return {
            "running": running,
            "connected": ISOLATION_NETWORK in networks,
            "ip": endpoint.get("IPAddress") or None,
        }
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise IsolationError(502, "Unexpected docker output")


def _log(db, alert_id, ip, container, action, result, detail) -> None:
    db.execute(
        "INSERT INTO isolation_log (alert_id, ip, container, action, result, detail, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (alert_id, None if ip is None else str(ip)[:64], container, action, result, detail, now().isoformat()),
    )
    db.commit()


def isolate(db, alert_id: int, token: str) -> Dict[str, Any]:
    row = db.execute("SELECT id, src_ip FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise IsolationError(404, "Alert not found")
    ip = row["src_ip"]
    container = ISOLATION_TARGETS.get(ip)
    if container is None:
        _log(db, alert_id, ip, None, "isolate", "fail", "target not allowed")
        raise IsolationError(403, "Target not allowed")
    with _DOCKER_LOCK:
        try:
            _check_token(alert_id, token)
            state = inspect_target(container)
            if not state["running"]:
                raise IsolationError(409, "Target container is not running")
            already = not state["connected"]
            if not already:
                _run_docker(["network", "disconnect", ISOLATION_NETWORK, container])
                if inspect_target(container)["connected"]:
                    raise IsolationError(502, "Isolation not confirmed")
        except IsolationError as exc:
            _log(db, alert_id, ip, container, "isolate", "fail", exc.detail)
            raise
        _consume_token(alert_id)
        _log(db, alert_id, ip, container, "isolate", "ok", "already isolated" if already else "isolated")
    return {"status": "already_isolated" if already else "isolated", "ip": ip, "container": container}


def unisolate(db, alert_id: Optional[int] = None, ip: Optional[str] = None) -> Dict[str, Any]:
    if alert_id is not None:
        row = db.execute("SELECT id, src_ip FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            raise IsolationError(404, "Alert not found")
        ip = row["src_ip"]
    container = ISOLATION_TARGETS.get(ip)
    if container is None:
        _log(db, alert_id, ip, None, "unisolate", "fail", "target not allowed")
        raise IsolationError(403, "Target not allowed")
    # Use the map key itself (not the request string) as the address to restore.
    target_ip = next(key for key, name in ISOLATION_TARGETS.items() if name == container)
    with _DOCKER_LOCK:
        try:
            state = inspect_target(container)
            if not state["running"]:
                raise IsolationError(409, "Target container is not running")
            if state["connected"]:
                if state["ip"] != target_ip:
                    raise IsolationError(409, "Target connected with unexpected IP")
                already = True
            else:
                already = False
                _run_docker(["network", "connect", "--ip", target_ip, ISOLATION_NETWORK, container])
                after = inspect_target(container)
                if not after["connected"] or after["ip"] != target_ip:
                    raise IsolationError(502, "IP not restored")
        except IsolationError as exc:
            _log(db, alert_id, target_ip, container, "unisolate", "fail", exc.detail)
            raise
        _log(db, alert_id, target_ip, container, "unisolate", "ok", "already connected" if already else "restored")
    return {"status": "already_connected" if already else "unisolated", "ip": target_ip, "container": container}


def _logged_isolated_ips(db) -> List[str]:
    isolated = []
    for ip in ISOLATION_TARGETS:
        last = db.execute(
            "SELECT action FROM isolation_log WHERE ip = ? AND result = 'ok' ORDER BY id DESC LIMIT 1", (ip,)
        ).fetchone()
        if last is not None and last["action"] == "isolate":
            isolated.append(ip)
    return isolated


def status(db) -> Dict[str, Any]:
    source = "log"
    docker_error = None
    isolated = _logged_isolated_ips(db)
    if enabled():
        try:
            live = []
            with _DOCKER_LOCK:
                for ip, container in ISOLATION_TARGETS.items():
                    state = inspect_target(container)
                    if state["running"] and not state["connected"]:
                        live.append(ip)
            isolated = live
            source = "docker"
        except IsolationError as exc:
            docker_error = exc.detail
    recent = [
        dict(r)
        for r in db.execute(
            "SELECT id, alert_id, ip, container, action, result, detail, created_at "
            "FROM isolation_log ORDER BY id DESC LIMIT ?",
            (RECENT_LOG_LIMIT,),
        ).fetchall()
    ]
    return {
        "enabled": enabled(),
        "allowed_ips": list(ISOLATION_TARGETS),
        "isolated_ips": isolated,
        "source": source,
        "docker_error": docker_error,
        "recent": recent,
    }
