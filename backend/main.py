import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.eve_parser import parse_eve_file

BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

CREATE_ALERTS_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS alerts ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "timestamp TEXT NOT NULL, "
    "flow_id INTEGER, "
    "sid INTEGER, "
    "category TEXT, "
    "signature TEXT, "
    "mitre_id TEXT, "
    "src_ip TEXT, "
    "dest_ip TEXT, "
    "dest_port INTEGER, "
    "http_status INTEGER, "
    "severity TEXT, "
    "is_confirmed_risk INTEGER DEFAULT 0, "
    "pii_masked INTEGER DEFAULT 0, "
    "raw_url TEXT, "
    "verdict TEXT DEFAULT 'UNREVIEWED', "
    "observation TEXT DEFAULT '', "
    "assessment TEXT DEFAULT '', "
    "confidence TEXT DEFAULT 'MEDIUM'"
    ");"
)

INSERT_ALERT_SQL = (
    "INSERT INTO alerts ("
    "timestamp, flow_id, sid, category, signature, mitre_id, "
    "src_ip, dest_ip, dest_port, http_status, severity, "
    "is_confirmed_risk, pii_masked, raw_url"
    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


class UploadResponse(BaseModel):
    upload_id: str
    alerts_stored: int
    skipped_lines: int
    returncode: int


class StatsResponse(BaseModel):
    total: int
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    mitre_coverage: list[str]


def get_allowed_origins() -> list[str]:
    raw = os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:5500,http://127.0.0.1:5500",
    )
    origins = [o.strip() for o in raw.split(",") if o.strip() and o.strip() != "*"]
    return origins or ["http://localhost:5500", "http://127.0.0.1:5500"]


def get_db_path() -> Path:
    return Path(os.environ.get("DB_PATH", str(BACKEND_DIR / "data" / "alerts.db")))


def get_upload_dir() -> Path:
    return Path(os.environ.get("UPLOAD_DIR", str(BACKEND_DIR / "data" / "uploads")))


def get_suricata_out_root() -> Path:
    return Path(
        os.environ.get("SURICATA_OUT_ROOT", str(BACKEND_DIR / "data" / "suricata_out"))
    )


def get_rules_path() -> Path:
    env_rules = os.environ.get("RULES_PATH")
    if env_rules:
        return Path(env_rules)
    return REPO_ROOT / "rules" / "custom.rules"


def get_suricata_bin() -> str:
    return os.environ.get("SURICATA_BIN", "suricata")


def get_suricata_timeout() -> int:
    try:
        return int(os.environ.get("SURICATA_TIMEOUT", "120"))
    except ValueError:
        return 120


def get_db_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(CREATE_ALERTS_TABLE_SQL)
    conn.commit()
    return conn


def store_alerts(alerts: list[dict[str, Any]]) -> int:
    if not alerts:
        get_db_connection().close()
        return 0

    rows = [
        (
            a["timestamp"],
            a["flow_id"],
            a["sid"],
            a["category"],
            a["signature"],
            a["mitre_id"],
            a["src_ip"],
            a["dest_ip"],
            a["dest_port"],
            a["http_status"],
            a["severity"],
            a["is_confirmed_risk"],
            a["pii_masked"],
            a["raw_url"],
        )
        for a in alerts
    ]
    with closing(get_db_connection()) as conn:
        conn.executemany(INSERT_ALERT_SQL, rows)
        conn.commit()
    return len(rows)


app = FastAPI(title="RookiRooki Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.post("/api/pcap/upload", response_model=UploadResponse)
async def upload_pcap(file: UploadFile = File(...)) -> UploadResponse:
    filename = file.filename or ""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Invalid file extension. Only .pcap and .pcapng are allowed.",
        )

    upload_dir = get_upload_dir()
    upload_dir.mkdir(parents=True, exist_ok=True)

    upload_id = uuid4().hex
    pcap_path = upload_dir / f"{upload_id}{ext}"

    total_bytes = 0
    try:
        with pcap_path.open("wb") as out_file:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    out_file.close()
                    pcap_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail="Uploaded file exceeds 20MB limit.",
                    )
                out_file.write(chunk)
    except HTTPException:
        pcap_path.unlink(missing_ok=True)
        raise

    rules_path = get_rules_path()
    if not rules_path.is_file():
        pcap_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="rules/custom.rules not found")

    outdir = get_suricata_out_root() / upload_id
    outdir.mkdir(parents=True, exist_ok=True)

    suricata_bin = get_suricata_bin()
    suricata_timeout = get_suricata_timeout()

    try:
        # Run in a worker thread so a long analysis does not block other API requests.
        proc = await run_in_threadpool(
            subprocess.run,
            [
                suricata_bin,
                "-r",
                str(pcap_path),
                "-S",
                str(rules_path),
                "-l",
                str(outdir),
                "-k",
                "none",
            ],
            capture_output=True,
            text=True,
            timeout=suricata_timeout,
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Suricata binary is not available.",
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Suricata analysis timed out.",
        )

    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip()[-300:]
        msg = f"Suricata failed with code {proc.returncode}"
        if stderr_tail:
            msg = f"{msg}: {stderr_tail}"
        raise HTTPException(status_code=502, detail=msg)

    eve_path = outdir / "eve.json"
    alerts, skipped_lines = parse_eve_file(eve_path)
    alerts_stored = store_alerts(alerts)

    return UploadResponse(
        upload_id=upload_id,
        alerts_stored=alerts_stored,
        skipped_lines=skipped_lines,
        returncode=proc.returncode,
    )


@app.get("/api/stats", response_model=StatsResponse)
def get_stats() -> StatsResponse:
    with closing(get_db_connection()) as conn:
        total_row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        total = int(total_row[0]) if total_row else 0

        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) FROM alerts WHERE severity IS NOT NULL GROUP BY severity"
        ).fetchall()
        severity_counts = {str(row[0]): int(row[1]) for row in sev_rows}

        cat_rows = conn.execute(
            "SELECT category, COUNT(*) FROM alerts WHERE category IS NOT NULL GROUP BY category"
        ).fetchall()
        category_counts = {str(row[0]): int(row[1]) for row in cat_rows}

        mitre_rows = conn.execute(
            "SELECT DISTINCT mitre_id FROM alerts WHERE mitre_id IS NOT NULL ORDER BY mitre_id"
        ).fetchall()
        mitre_coverage = [str(row[0]) for row in mitre_rows]

    return StatsResponse(
        total=total,
        severity_counts=severity_counts,
        category_counts=category_counts,
        mitre_coverage=mitre_coverage,
    )
