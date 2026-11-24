import json
import re
from pathlib import Path
from typing import Any, Iterable

SID_MAP: dict[int, dict[str, str]] = {
    1000001: {"category": "sqli", "severity": "SEV3", "mitre_id": "T1190"},
    1000002: {"category": "xss", "severity": "SEV3", "mitre_id": "T1189"},
    1000003: {"category": "bruteforce", "severity": "SEV2", "mitre_id": "T1110.001"},
    1000004: {"category": "portscan", "severity": "SEV3", "mitre_id": "T1046"},
}

ESCALATABLE_CATEGORIES = {"sqli", "xss"}

PII_PATTERN = re.compile(
    r"\b(password|passwd|pwd|token|secret)=([^\s&]*)",
    re.IGNORECASE,
)


def mask_sensitive_text(text: str | None) -> tuple[str | None, int]:
    """Mask sensitive key=value pairs in text and return (masked_text, pii_masked_flag)."""
    if text is None:
        return None, 0
    masked, count = PII_PATTERN.subn(r"\1=[MASKED]", text)
    return masked, (1 if count > 0 else 0)


def _extract_tx_id(event: dict[str, Any]) -> Any:
    if "tx_id" in event and event["tx_id"] is not None:
        return event["tx_id"]
    http_obj = event.get("http")
    if isinstance(http_obj, dict) and http_obj.get("tx_id") is not None:
        return http_obj.get("tx_id")
    return None


def _extract_url(event: dict[str, Any]) -> str | None:
    http_obj = event.get("http")
    if isinstance(http_obj, dict) and isinstance(http_obj.get("url"), str):
        return http_obj["url"]
    if isinstance(event.get("url"), str):
        return event["url"]
    return None


def _extract_status(event: dict[str, Any]) -> int | None:
    http_obj = event.get("http")
    if isinstance(http_obj, dict) and http_obj.get("status") is not None:
        try:
            return int(http_obj["status"])
        except (ValueError, TypeError):
            return None
    return None


def find_paired_http_event(
    alert_event: dict[str, Any],
    flow_http_events: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find the HTTP event belonging to the exact same attack request on the same flow."""
    if not flow_http_events:
        return None

    alert_tx_id = _extract_tx_id(alert_event)
    alert_url = _extract_url(alert_event)

    for http_event in flow_http_events:
        http_tx_id = _extract_tx_id(http_event)
        http_url = _extract_url(http_event)

        if alert_tx_id is not None and http_tx_id is not None:
            if alert_tx_id == http_tx_id:
                return http_event
        else:
            if alert_url is not None and http_url is not None and alert_url == http_url:
                return http_event

    if alert_tx_id is None and alert_url is None and len(flow_http_events) == 1:
        return flow_http_events[0]

    return None


def compute_escalation(
    category: str,
    base_severity: str,
    http_status: int | None,
) -> tuple[str, int]:
    """Return (severity, is_confirmed_risk) according to category and HTTP status."""
    if category in ESCALATABLE_CATEGORIES and http_status == 200:
        return "SEV1", 1
    return base_severity, 0


def parse_eve_lines(lines: Iterable[str]) -> tuple[list[dict[str, Any]], int]:
    """Parse NDJSON lines from eve.json and return (parsed_alerts, skipped_lines)."""
    skipped_lines = 0
    raw_alerts: list[dict[str, Any]] = []
    http_by_flow: dict[Any, list[dict[str, Any]]] = {}

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            skipped_lines += 1
            continue

        if not isinstance(event, dict):
            skipped_lines += 1
            continue

        event_type = event.get("event_type")
        if event_type == "http":
            flow_id = event.get("flow_id")
            if flow_id is not None:
                http_by_flow.setdefault(flow_id, []).append(event)
        elif event_type == "alert":
            raw_alerts.append(event)

    results: list[dict[str, Any]] = []
    for event in raw_alerts:
        alert_info = event.get("alert")
        if not isinstance(alert_info, dict):
            continue

        raw_sid = alert_info.get("signature_id")
        try:
            sid = int(raw_sid)
        except (ValueError, TypeError):
            continue

        if sid not in SID_MAP:
            continue

        meta = SID_MAP[sid]
        category = meta["category"]
        base_severity = meta["severity"]
        mitre_id = meta["mitre_id"]

        flow_id = event.get("flow_id")
        flow_http_events = http_by_flow.get(flow_id, []) if flow_id is not None else []
        paired_http = find_paired_http_event(event, flow_http_events)

        if paired_http is not None:
            http_status = _extract_status(paired_http)
            if http_status is None:
                http_status = _extract_status(event)
            raw_url = _extract_url(event) or _extract_url(paired_http)
        else:
            http_status = _extract_status(event)
            raw_url = _extract_url(event)

        severity, is_confirmed_risk = compute_escalation(
            category=category,
            base_severity=base_severity,
            http_status=http_status,
        )

        raw_signature = str(alert_info.get("signature") or "")
        masked_url, url_masked = mask_sensitive_text(raw_url)
        masked_signature, sig_masked = mask_sensitive_text(raw_signature)
        pii_masked = 1 if (url_masked or sig_masked) else 0

        results.append(
            {
                "timestamp": str(event.get("timestamp") or ""),
                "flow_id": flow_id,
                "sid": sid,
                "category": category,
                "signature": masked_signature or "",
                "mitre_id": mitre_id,
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "http_status": http_status,
                "severity": severity,
                "is_confirmed_risk": is_confirmed_risk,
                "pii_masked": pii_masked,
                "raw_url": masked_url,
            }
        )

    return results, skipped_lines


def parse_eve_file(eve_path: str | Path) -> tuple[list[dict[str, Any]], int]:
    """Read an eve.json file and return (parsed_alerts, skipped_lines)."""
    path = Path(eve_path)
    if not path.is_file():
        return [], 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return parse_eve_lines(f)
