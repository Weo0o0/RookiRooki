import ipaddress
import json
import logging
import os
import sqlite3
import tempfile
import threading
import time
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .eve_parser import mask_text, parse_eve

ROOT = Path(__file__).resolve().parent.parent
LAB_NET = ipaddress.ip_network("172.28.0.0/24")
CONTEXT_HTTP_LINES = 200
MAX_BATCH_BYTES = 8 * 1024 * 1024

def _new_state():
    return {
        "offset": 0,
        "last_poll_at": None,
        "rows_stored": 0,
        "rows_skipped_out_of_scope": 0,
        "last_error": None,
        "http_context": deque(maxlen=CONTEXT_HTTP_LINES),
    }

STATE = _new_state()
_thread = None

def enabled():
    return os.getenv("LIVE_CAPTURE_ENABLED") == "1"

def eve_path():
    return Path(os.getenv("LIVE_EVE_PATH", str(ROOT / "backend" / "data" / "live" / "eve.json")))

def poll_seconds():
    try:
        value = float(os.getenv("LIVE_POLL_SECONDS", "2"))
    except ValueError:
        return 2.0
    return value if value > 0 else 2.0

def _in_lab(ip):
    try:
        return ipaddress.ip_address(ip) in LAB_NET
    except ValueError:
        return False

def _log_dir():
    parent = eve_path().parent
    try:
        return parent.relative_to(ROOT).as_posix()
    except ValueError:
        return parent.as_posix()

def status():
    return {
        "enabled": enabled(),
        "eve_path": str(eve_path()),
        "offset": STATE["offset"],
        "last_poll_at": STATE["last_poll_at"],
        "rows_stored": STATE["rows_stored"],
        "rows_skipped_out_of_scope": STATE["rows_skipped_out_of_scope"],
        "last_error": STATE["last_error"],
        "start_command": (
            f"sudo suricata -i br-minisiem -S rules/custom.rules -l {_log_dir()} -k none "
            "--user $(id -un) --group $(id -gn) 'net 172.28.0.0/24'"
        ),
        "stop_command": "Ctrl+C in the Suricata terminal, or: sudo pkill -f '^suricata -i br-minisiem'",
    }

def save(db, eve_file, offset):
    db.execute(
        "INSERT OR REPLACE INTO live_capture_state (eve_path, offset, updated_at) VALUES (?, ?, ?)",
        (str(eve_file), offset, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    STATE["offset"] = offset

def _apply_late_http(db, chunk):
    # An http event that arrives after its alert row was stored: fill in status/severity once.
    for line in chunk.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("event_type") != "http":
            continue
        data = event.get("http") if isinstance(event.get("http"), dict) else {}
        status = data.get("status")
        if event.get("flow_id") is None or isinstance(status, bool) or not isinstance(status, int):
            continue
        url = mask_text(data.get("url") or "")[0]
        severity = "SEV1" if status == 200 else "SEV3"
        db.execute(
            "UPDATE alerts SET http_status = ?, severity = ?, is_confirmed_risk = ? "
            "WHERE flow_id = ? AND category IN ('sqli','xss','ssrf') AND http_status IS NULL "
            "AND (? = '' OR IFNULL(raw_url, '') = '' OR raw_url = ?)",
            (status, severity, int(severity == "SEV1"), event["flow_id"], url, url),
        )

def _poll(db_file, eve_file, insert_rows):
    with closing(sqlite3.connect(db_file)) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS live_capture_state ("
            "eve_path TEXT PRIMARY KEY, offset INTEGER NOT NULL, updated_at TEXT)"
        )
        saved = db.execute("SELECT offset FROM live_capture_state WHERE eve_path = ?", (str(eve_file),)).fetchone()
        offset = saved[0] if saved else 0
        STATE["offset"] = offset
        if not Path(eve_file).is_file():
            return
        if Path(eve_file).stat().st_size < offset:  # rotated or truncated
            offset = 0
            STATE["http_context"].clear()
            save(db, eve_file, 0)
        with open(eve_file, "rb") as handle:
            handle.seek(offset)
            data = handle.read(MAX_BATCH_BYTES)
        end = data.rfind(b"\n")
        if end < 0:  # nothing new, or only a partial line: wait for the next poll
            return
        chunk = data[: end + 1]

        with tempfile.TemporaryDirectory() as tmp:
            batch = Path(tmp) / "batch.json"
            batch.write_bytes(b"".join(STATE["http_context"]) + chunk)
            rows, _ = parse_eve(batch)

        in_scope = [r for r in rows if _in_lab(r["src_ip"]) and _in_lab(r["dest_ip"])]
        stored = insert_rows(db, in_scope)
        _apply_late_http(db, chunk)
        save(db, eve_file, offset + len(chunk))

        STATE["rows_stored"] += stored
        STATE["rows_skipped_out_of_scope"] += len(rows) - len(in_scope)
        for line in chunk.splitlines(keepends=True):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("event_type") == "http":
                STATE["http_context"].append(line)

def poll_once(db_file, eve_file, insert_rows):
    try:
        _poll(db_file, eve_file, insert_rows)
        STATE["last_error"] = None
    except Exception as exc:
        logging.exception("live capture poll failed")
        STATE["last_error"] = type(exc).__name__
    STATE["last_poll_at"] = datetime.now(timezone.utc).isoformat()

def _run(db_path, insert_rows):
    while True:
        poll_once(db_path(), eve_path(), insert_rows)
        time.sleep(poll_seconds())

def start(db_path, insert_rows):
    global _thread
    if not enabled() or (_thread is not None and _thread.is_alive()):
        return
    _thread = threading.Thread(target=_run, args=(db_path, insert_rows), name="live-capture", daemon=True)
    _thread.start()
