import logging
import os
import sqlite3
import subprocess
import uuid
from contextlib import closing
from typing import Dict, List
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .eve_parser import parse_eve

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
ROOT = Path(__file__).resolve().parent.parent
app = FastAPI()
origins = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",") if x.strip()]
origins = [origin for origin in origins if origin != "*"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

class UploadResult(BaseModel):
    upload_id: str
    alerts_stored: int
    skipped_lines: int

class StatsResult(BaseModel):
    total: int
    severity_counts: Dict[str, int]
    category_counts: Dict[str, int]
    mitre_coverage: List[str]

def config(name, default):
    return Path(os.getenv(name, str(default)))

def db_path():
    return config("DB_PATH", ROOT / "backend" / "data" / "alerts.db")

def init_db():
    path = db_path(); path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, flow_id INTEGER, sid INTEGER, category TEXT, signature TEXT, mitre_id TEXT, src_ip TEXT, dest_ip TEXT, dest_port INTEGER, http_status INTEGER, severity TEXT, is_confirmed_risk INTEGER DEFAULT 0, pii_masked INTEGER DEFAULT 0, raw_url TEXT, verdict TEXT DEFAULT 'UNREVIEWED', observation TEXT DEFAULT '', assessment TEXT DEFAULT '', confidence TEXT DEFAULT 'MEDIUM')")
        db.commit()

def store(rows):
    init_db()
    keys = ("timestamp", "flow_id", "sid", "category", "signature", "mitre_id", "src_ip", "dest_ip", "dest_port", "http_status", "severity", "is_confirmed_risk", "pii_masked", "raw_url")
    sql = "INSERT INTO alerts (timestamp,flow_id,sid,category,signature,mitre_id,src_ip,dest_ip,dest_port,http_status,severity,is_confirmed_risk,pii_masked,raw_url) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    with closing(sqlite3.connect(db_path())) as db:
        db.executemany(sql, [tuple(row[k] for k in keys) for row in rows]); db.commit()

def run_suricata(pcap, outdir, rules):
    command = [os.getenv("SURICATA_BIN", "suricata"), "-r", str(pcap), "-S", str(rules), "-l", str(outdir), "-k", "none"]
    return subprocess.run(command, capture_output=True, text=True, timeout=int(os.getenv("SURICATA_TIMEOUT", "120")))

@app.post("/api/pcap/upload", response_model=UploadResult)
async def upload(file: UploadFile = File(...)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(400, "Only .pcap and .pcapng files are accepted")
    upload_id = uuid.uuid4().hex
    upload_dir = config("UPLOAD_DIR", ROOT / "backend" / "data" / "uploads")
    out_root = config("SURICATA_OUT_ROOT", ROOT / "backend" / "data" / "suricata")
    rules = config("RULES_PATH", ROOT / "rules" / "custom.rules")
    if not rules.exists():
        raise HTTPException(500, "rules/custom.rules not found")
    upload_dir.mkdir(parents=True, exist_ok=True); outdir = out_root / upload_id; outdir.mkdir(parents=True, exist_ok=True)
    pcap = upload_dir / f"{upload_id}{ext}"; size = 0
    try:
        with open(pcap, "wb") as target:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "Upload too large")
                target.write(chunk)
        try:
            result = await run_in_threadpool(run_suricata, pcap, outdir, rules)
        except FileNotFoundError:
            raise HTTPException(503, "Suricata unavailable")
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "Suricata timed out")
        if result.returncode != 0:
            logging.error("Suricata failed (%s): %s", result.returncode, result.stderr)
            raise HTTPException(502, f"Suricata failed with return code {result.returncode}")
        eve_path = outdir / "eve.json"
        rows, skipped = parse_eve(eve_path) if eve_path.exists() else ([], 0)
        store(rows)
        return UploadResult(upload_id=upload_id, alerts_stored=len(rows), skipped_lines=skipped)
    finally:
        if size > MAX_UPLOAD_BYTES and pcap.exists():
            pcap.unlink()

@app.get("/api/stats", response_model=StatsResult)
def stats():
    init_db()
    with closing(sqlite3.connect(db_path())) as db:
        total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        severity = dict(db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
        category = dict(db.execute("SELECT category, COUNT(*) FROM alerts GROUP BY category").fetchall())
        mitre = [row[0] for row in db.execute("SELECT DISTINCT mitre_id FROM alerts WHERE mitre_id IS NOT NULL ORDER BY mitre_id").fetchall()]
    return {"total": total, "severity_counts": severity, "category_counts": category, "mitre_coverage": mitre}
