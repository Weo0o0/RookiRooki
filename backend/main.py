import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .eve_parser import extract_event_types, mask_text, parse_eve

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
ROOT = Path(__file__).resolve().parent.parent
app = FastAPI()
origins = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",") if x.strip()]
origins = [origin for origin in origins if origin != "*"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

ALERT_KEYS = (
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
)

class UploadResult(BaseModel):
    upload_id: str
    alerts_stored: int
    duplicates_skipped: int
    skipped_lines: int
    duplicate_of: Optional[str] = None

class IngestSampleResult(BaseModel):
    alerts_stored: int
    duplicates_skipped: int
    skipped_lines: int

class BlindRule(BaseModel):
    sid: int
    category: str
    title: str
    missing_sources: List[str]

class StatsResult(BaseModel):
    total: int
    severity_counts: Dict[str, int]
    category_counts: Dict[str, int]
    mitre_coverage: List[str]
    blind_rules: List[BlindRule]

class TriageUpdate(BaseModel):
    model_config = {"extra": "forbid"}

    verdict: Optional[Literal["TP", "FP", "UNREVIEWED"]] = None
    confidence: Optional[Literal["HIGH", "MEDIUM", "LOW"]] = None
    observation: Optional[str] = Field(None, max_length=2000)
    assessment: Optional[str] = Field(None, max_length=2000)

def config(name, default):
    return Path(os.getenv(name, str(default)))

def db_path():
    return config("DB_PATH", ROOT / "backend" / "data" / "alerts.db")

def sample_eve_path():
    return config("SAMPLE_EVE_PATH", ROOT / "scenarios" / "sample_eve.json")

def playbooks_path():
    return config("PLAYBOOKS_PATH", ROOT / "scenarios" / "playbooks.json")

def rule_catalog_path():
    return config("RULE_CATALOG_PATH", ROOT / "rules" / "rule_catalog.json")

def init_db():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute(
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
            "confidence TEXT DEFAULT 'MEDIUM')"
        )
        db.execute("DROP INDEX IF EXISTS ux_alert_identity")
        try:
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_identity_v2 ON alerts("
                "timestamp, sid, IFNULL(src_ip,''), IFNULL(dest_ip,''), "
                "IFNULL(dest_port,-1), IFNULL(raw_url,''))"
            )
        except sqlite3.OperationalError as exc:
            logging.warning("Failed to create ux_alert_identity_v2 index (existing duplicates?): %s", exc)

        db.execute(
            "CREATE TABLE IF NOT EXISTS pcap_uploads ("
            "sha256 TEXT PRIMARY KEY, "
            "upload_id TEXT, "
            "alerts_stored INTEGER, "
            "created_at TEXT)"
        )
        db.execute("CREATE TABLE IF NOT EXISTS ingest_sources (source TEXT PRIMARY KEY)")
        db.execute("CREATE TABLE IF NOT EXISTS ingest_meta (key TEXT PRIMARY KEY, value TEXT)")
        db.commit()

def ingest_eve(path):
    init_db()
    rows, skipped = parse_eve(path) if Path(path).exists() else ([], 0)
    event_types = extract_event_types(path) if Path(path).exists() else set()
    sources = [f"suricata_{et}" for et in event_types]

    keys = (
        "timestamp",
        "flow_id",
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
    )
    sql = (
        "INSERT OR IGNORE INTO alerts "
        "(timestamp,flow_id,sid,category,signature,mitre_id,src_ip,dest_ip,dest_port,http_status,severity,is_confirmed_risk,pii_masked,raw_url) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    )

    stored = 0
    with closing(sqlite3.connect(db_path())) as db:
        for row in rows:
            cursor = db.execute(sql, tuple(row[k] for k in keys))
            if cursor.rowcount > 0:
                stored += 1

        db.execute("DELETE FROM ingest_sources")
        for s in sources:
            db.execute("INSERT OR REPLACE INTO ingest_sources (source) VALUES (?)", (s,))
        db.execute(
            "INSERT OR REPLACE INTO ingest_meta (key, value) VALUES ('last_ingest_at', ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        db.commit()

    duplicates = len(rows) - stored
    return stored, duplicates, skipped

def load_playbooks() -> Dict[str, Any]:
    path = playbooks_path()
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def load_rule_catalog() -> Optional[List[Dict[str, Any]]]:
    path = rule_catalog_path()
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else None
    except Exception:
        return None

def build_alert_dict(row, playbooks: Dict[str, Any]) -> Dict[str, Any]:
    category = row["category"]
    raw_playbook = playbooks.get(category) if category else None
    playbook_entry = None
    if isinstance(raw_playbook, dict):
        playbook_entry = dict(raw_playbook)
        raw_analysis = playbook_entry.get("analysis")
        normalized_analysis = []
        if isinstance(raw_analysis, list):
            for item in raw_analysis:
                if not isinstance(item, dict):
                    continue
                cmd = item.get("command")
                tokens = item.get("tokens")
                if not isinstance(cmd, str) or not isinstance(tokens, list):
                    continue
                masked_cmd, _ = mask_text(cmd)
                norm_tokens = []
                for tok in tokens:
                    if not isinstance(tok, dict):
                        continue
                    t_val = tok.get("token")
                    d_val = tok.get("desc")
                    masked_tok, _ = mask_text(t_val) if t_val is not None else ("", False)
                    masked_desc, _ = mask_text(d_val) if d_val is not None else ("", False)
                    norm_tokens.append({
                        "token": masked_tok,
                        "desc": masked_desc,
                    })
                normalized_analysis.append({
                    "title": str(item.get("title", "") or ""),
                    "where": str(item.get("where", "") or ""),
                    "command": masked_cmd,
                    "tokens": norm_tokens,
                })
        playbook_entry["analysis"] = normalized_analysis

    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "sid": row["sid"],
        "category": row["category"],
        "signature": row["signature"],
        "mitre_id": row["mitre_id"],
        "src_ip": row["src_ip"],
        "dest_ip": row["dest_ip"],
        "dest_port": row["dest_port"],
        "http_status": row["http_status"],
        "severity": row["severity"],
        "is_confirmed_risk": row["is_confirmed_risk"],
        "pii_masked": row["pii_masked"],
        "raw_url": row["raw_url"],
        "verdict": row["verdict"],
        "observation": row["observation"],
        "assessment": row["assessment"],
        "confidence": row["confidence"],
        "playbook": playbook_entry,
    }

def run_suricata(pcap, outdir, rules):
    command = [
        os.getenv("SURICATA_BIN", "suricata"),
        "-r", str(pcap),
        "-S", str(rules),
        "-l", str(outdir),
        "-k", "none",
        "--runmode", "single",
    ]
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
    upload_dir.mkdir(parents=True, exist_ok=True)
    outdir = out_root / upload_id
    outdir.mkdir(parents=True, exist_ok=True)
    pcap = upload_dir / f"{upload_id}{ext}"
    size = 0
    hasher = hashlib.sha256()
    try:
        with open(pcap, "wb") as target:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "Upload too large")
                target.write(chunk)
                hasher.update(chunk)

        file_hash = hasher.hexdigest()
        init_db()
        with closing(sqlite3.connect(db_path())) as db:
            existing = db.execute(
                "SELECT upload_id, alerts_stored FROM pcap_uploads WHERE sha256 = ?",
                (file_hash,),
            ).fetchone()

        if existing:
            prev_upload_id, prev_stored = existing
            if pcap.exists():
                pcap.unlink()
            if outdir.exists():
                try:
                    outdir.rmdir()
                except OSError:
                    pass
            return UploadResult(
                upload_id=upload_id,
                alerts_stored=0,
                duplicates_skipped=prev_stored,
                skipped_lines=0,
                duplicate_of=prev_upload_id,
            )

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
        stored, duplicates, skipped = ingest_eve(eve_path)

        with closing(sqlite3.connect(db_path())) as db:
            db.execute(
                "INSERT OR REPLACE INTO pcap_uploads (sha256, upload_id, alerts_stored, created_at) VALUES (?, ?, ?, ?)",
                (file_hash, upload_id, stored, datetime.now(timezone.utc).isoformat()),
            )
            db.commit()

        return UploadResult(
            upload_id=upload_id,
            alerts_stored=stored,
            duplicates_skipped=duplicates,
            skipped_lines=skipped,
            duplicate_of=None,
        )
    finally:
        if size > MAX_UPLOAD_BYTES and pcap.exists():
            pcap.unlink()
            if outdir.exists():
                try:
                    outdir.rmdir()
                except OSError:
                    pass

@app.post("/api/ingest/sample", response_model=IngestSampleResult)
def ingest_sample():
    sample_path = sample_eve_path()
    if not sample_path.is_file():
        raise HTTPException(404, detail="scenarios/sample_eve.json not found")
    stored, duplicates, skipped = ingest_eve(sample_path)
    return IngestSampleResult(
        alerts_stored=stored,
        duplicates_skipped=duplicates,
        skipped_lines=skipped,
    )

@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = Query(None, pattern=r"^(SEV1|SEV2|SEV3|SEV4)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    init_db()
    playbooks = load_playbooks()
    with closing(sqlite3.connect(db_path())) as db:
        db.row_factory = sqlite3.Row
        if severity is not None:
            total = db.execute("SELECT COUNT(*) FROM alerts WHERE severity = ?", (severity,)).fetchone()[0]
            rows = db.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (severity, limit, offset),
            ).fetchall()
        else:
            total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            rows = db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

    items = [build_alert_dict(row, playbooks) for row in rows]
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }

@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: int):
    init_db()
    playbooks = load_playbooks()
    with closing(sqlite3.connect(db_path())) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(404, detail="Alert not found")
    return build_alert_dict(row, playbooks)

@app.patch("/api/alerts/{alert_id}/triage")
def update_triage(alert_id: int, payload: TriageUpdate):
    init_db()
    provided = payload.model_dump(exclude_unset=True)
    if not provided:
        raise HTTPException(422, detail="At least one field is required for triage update")

    masked_obs = None
    if "observation" in provided:
        raw_obs = provided["observation"]
        masked_obs, _ = mask_text(raw_obs) if raw_obs is not None else (None, False)

    masked_assess = None
    if "assessment" in provided:
        raw_assess = provided["assessment"]
        masked_assess, _ = mask_text(raw_assess) if raw_assess is not None else (None, False)

    v_val = provided.get("verdict")
    o_val = masked_obs
    a_val = masked_assess
    c_val = provided.get("confidence")

    playbooks = load_playbooks()
    with closing(sqlite3.connect(db_path())) as db:
        db.row_factory = sqlite3.Row
        exists = db.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not exists:
            raise HTTPException(404, detail="Alert not found")

        sql = (
            "UPDATE alerts SET "
            "verdict = COALESCE(?, verdict), "
            "observation = COALESCE(?, observation), "
            "assessment = COALESCE(?, assessment), "
            "confidence = COALESCE(?, confidence) "
            "WHERE id = ?"
        )
        db.execute(sql, (v_val, o_val, a_val, c_val, alert_id))
        db.commit()

        row = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    return build_alert_dict(row, playbooks)

@app.get("/api/stats", response_model=StatsResult)
def stats():
    init_db()
    with closing(sqlite3.connect(db_path())) as db:
        total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        severity = dict(db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
        category = dict(db.execute("SELECT category, COUNT(*) FROM alerts GROUP BY category").fetchall())
        mitre = [row[0] for row in db.execute("SELECT DISTINCT mitre_id FROM alerts WHERE mitre_id IS NOT NULL ORDER BY mitre_id").fetchall()]

        ingest_sources_rows = db.execute("SELECT source FROM ingest_sources").fetchall()
        present_sources = {row[0] for row in ingest_sources_rows}
        meta_ingest = db.execute("SELECT value FROM ingest_meta WHERE key = 'last_ingest_at'").fetchone()

    blind_rules: List[Dict[str, Any]] = []
    catalog = load_rule_catalog()
    if catalog is not None and meta_ingest is not None:
        for rule in catalog:
            if not isinstance(rule, dict):
                continue
            try:
                sid_raw = rule.get("sid")
                if sid_raw is None:
                    continue
                sid_val = int(sid_raw)
            except (ValueError, TypeError):
                continue

            category_val = str(rule.get("category", "") or "")
            title_val = str(rule.get("title", "") or "")

            rule_data_sources = rule.get("data_sources")
            if not isinstance(rule_data_sources, list):
                rule_data_sources = []

            missing = [str(s) for s in rule_data_sources if str(s) not in present_sources]
            if missing:
                blind_rules.append({
                    "sid": sid_val,
                    "category": category_val,
                    "title": title_val,
                    "missing_sources": missing,
                })

    return {
        "total": total,
        "severity_counts": severity,
        "category_counts": category,
        "mitre_coverage": mitre,
        "blind_rules": blind_rules,
    }
