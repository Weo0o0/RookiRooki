import json
import re

CATEGORIES = {1000001: ("sqli", "SEV3", "T1190"), 1000002: ("xss", "SEV3", "T1189"), 1000003: ("bruteforce", "SEV2", "T1110.001"), 1000004: ("portscan", "SEV3", "T1046")}
MASKED_KEYS = r"password|passwd|pwd|token|secret"

def mask_text(value):
    if value is None:
        return value, False
    text = str(value)
    pattern = re.compile(rf"(\b(?:{MASKED_KEYS})\b\s*=\s*)([^&\s]*)", re.I)
    text, a = pattern.subn(r"\1[MASKED]", text)
    pattern = re.compile(rf'("(?:{MASKED_KEYS})"\s*:\s*")(.*?)(")', re.I)
    text, b = pattern.subn(r"\1[MASKED]\3", text)
    return text, bool(a or b)

def _events_match(alert, http):
    if alert.get("flow_id") != http.get("flow_id"):
        return False
    atx, htx = alert.get("tx_id"), http.get("tx_id")
    if atx is not None and htx is not None:
        return atx == htx
    if alert.get("http", {}).get("url") and http.get("http", {}).get("url"):
        return alert["http"]["url"] == http["http"]["url"]
    return False

def parse_eve(path):
    events, skipped = [], 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    skipped += 1
                else:
                    events.append(item)
            except json.JSONDecodeError:
                skipped += 1
    alerts = [e for e in events if e.get("event_type") == "alert" and e.get("alert", {}).get("signature_id") in CATEGORIES]
    https = [e for e in events if e.get("event_type") == "http"]
    rows = []
    for event in alerts:
        alert = event.get("alert", {})
        sid = alert.get("signature_id")
        category, base, mitre = CATEGORIES[sid]
        candidates = [h for h in https if _events_match(event, h)]
        if not candidates and event.get("flow_id") is not None and event.get("tx_id") is None and not event.get("http", {}).get("url"):
            flow_events = [h for h in https if h.get("flow_id") == event.get("flow_id")]
            if len(flow_events) == 1:
                candidates = flow_events
        http = candidates[0] if candidates else None
        data = event.get("http", {})
        http_data = (http or {}).get("http", {})
        status = http_data.get("status", data.get("status"))
        url = http_data.get("url", data.get("url", ""))
        signature, m1 = mask_text(alert.get("signature", ""))
        raw_url, m2 = mask_text(url)
        severity = "SEV1" if category in ("sqli", "xss") and status == 200 else base
        rows.append({"timestamp": event.get("timestamp", ""), "flow_id": event.get("flow_id"), "sid": sid, "category": category, "signature": signature, "mitre_id": mitre, "src_ip": event.get("src_ip"), "dest_ip": event.get("dest_ip"), "dest_port": event.get("dest_port"), "http_status": status, "severity": severity, "is_confirmed_risk": int(severity == "SEV1"), "pii_masked": int(m1 or m2), "raw_url": raw_url})
    return rows, skipped
