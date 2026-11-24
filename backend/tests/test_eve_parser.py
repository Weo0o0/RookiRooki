import json

from backend.eve_parser import parse_eve_lines


def _dump_lines(events: list[str | dict]) -> list[str]:
    lines: list[str] = []
    for item in events:
        if isinstance(item, str):
            lines.append(item)
        else:
            lines.append(json.dumps(item))
    return lines


def test_sid_filtering_and_malformed_lines():
    lines = _dump_lines(
        [
            "not-valid-json{{{",
            "[1, 2, 3]",
            "42",
            {
                "timestamp": "2026-03-01T10:00:00Z",
                "flow_id": 1,
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "dest_port": 80,
                "alert": {"signature_id": 9999999, "signature": "Ignored SID"},
            },
            {
                "timestamp": "2026-03-01T10:00:01Z",
                "flow_id": 2,
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "dest_port": 80,
                "alert": {"signature_id": 1000001, "signature": "SQLi Attempt"},
            },
        ]
    )

    alerts, skipped = parse_eve_lines(lines)
    assert skipped == 3
    assert len(alerts) == 1
    assert alerts[0]["sid"] == 1000001
    assert alerts[0]["category"] == "sqli"
    assert alerts[0]["mitre_id"] == "T1190"


def test_pairing_by_flow_and_tx_id_and_sqli_escalation():
    lines = _dump_lines(
        [
            {
                "timestamp": "2026-03-01T10:01:00Z",
                "flow_id": 100,
                "tx_id": 0,
                "event_type": "http",
                "http": {"url": "/search?q=1'+OR+'1'='1", "status": 200},
            },
            {
                "timestamp": "2026-03-01T10:01:00Z",
                "flow_id": 100,
                "tx_id": 0,
                "event_type": "alert",
                "src_ip": "192.168.1.10",
                "dest_ip": "192.168.1.20",
                "dest_port": 8080,
                "alert": {"signature_id": 1000001, "signature": "SQLi Detected"},
            },
            {
                "timestamp": "2026-03-01T10:02:00Z",
                "flow_id": 101,
                "tx_id": 0,
                "event_type": "http",
                "http": {"url": "/search?q=1'+UNION+SELECT", "status": 404},
            },
            {
                "timestamp": "2026-03-01T10:02:00Z",
                "flow_id": 101,
                "tx_id": 0,
                "event_type": "alert",
                "src_ip": "192.168.1.10",
                "dest_ip": "192.168.1.20",
                "dest_port": 8080,
                "alert": {"signature_id": 1000001, "signature": "SQLi 404"},
            },
        ]
    )

    alerts, skipped = parse_eve_lines(lines)
    assert skipped == 0
    assert len(alerts) == 2

    sqli_200 = alerts[0]
    assert sqli_200["http_status"] == 200
    assert sqli_200["severity"] == "SEV1"
    assert sqli_200["is_confirmed_risk"] == 1

    sqli_404 = alerts[1]
    assert sqli_404["http_status"] == 404
    assert sqli_404["severity"] == "SEV3"
    assert sqli_404["is_confirmed_risk"] == 0


def test_two_requests_on_same_flow_does_not_escalate_from_other_request():
    lines = _dump_lines(
        [
            {
                "timestamp": "2026-03-01T10:03:00Z",
                "flow_id": 500,
                "tx_id": 1,
                "event_type": "http",
                "http": {"url": "/home", "status": 200},
            },
            {
                "timestamp": "2026-03-01T10:03:01Z",
                "flow_id": 500,
                "tx_id": 2,
                "event_type": "http",
                "http": {"url": "/admin?id=1'+OR+'1'='1", "status": 403},
            },
            {
                "timestamp": "2026-03-01T10:03:01Z",
                "flow_id": 500,
                "tx_id": 2,
                "event_type": "alert",
                "src_ip": "10.1.1.5",
                "dest_ip": "10.1.1.10",
                "dest_port": 80,
                "alert": {"signature_id": 1000002, "signature": "XSS Blocked"},
            },
        ]
    )

    alerts, _ = parse_eve_lines(lines)
    assert len(alerts) == 1
    assert alerts[0]["http_status"] == 403
    assert alerts[0]["severity"] == "SEV3"
    assert alerts[0]["is_confirmed_risk"] == 0


def test_bruteforce_and_portscan_not_escalated_on_200():
    lines = _dump_lines(
        [
            {
                "timestamp": "2026-03-01T10:04:00Z",
                "flow_id": 700,
                "tx_id": 0,
                "event_type": "http",
                "http": {"url": "/login", "status": 200},
            },
            {
                "timestamp": "2026-03-01T10:04:00Z",
                "flow_id": 700,
                "tx_id": 0,
                "event_type": "alert",
                "src_ip": "10.0.0.8",
                "dest_ip": "10.0.0.9",
                "dest_port": 80,
                "alert": {"signature_id": 1000003, "signature": "Bruteforce Login"},
            },
            {
                "timestamp": "2026-03-01T10:05:00Z",
                "flow_id": 701,
                "tx_id": 0,
                "event_type": "http",
                "http": {"url": "/", "status": 200},
            },
            {
                "timestamp": "2026-03-01T10:05:00Z",
                "flow_id": 701,
                "tx_id": 0,
                "event_type": "alert",
                "src_ip": "10.0.0.8",
                "dest_ip": "10.0.0.9",
                "dest_port": 22,
                "alert": {"signature_id": 1000004, "signature": "Portscan"},
            },
        ]
    )

    alerts, _ = parse_eve_lines(lines)
    assert len(alerts) == 2

    bf = alerts[0]
    assert bf["category"] == "bruteforce"
    assert bf["http_status"] == 200
    assert bf["severity"] == "SEV2"
    assert bf["is_confirmed_risk"] == 0
    assert bf["mitre_id"] == "T1110.001"

    ps = alerts[1]
    assert ps["category"] == "portscan"
    assert ps["http_status"] == 200
    assert ps["severity"] == "SEV3"
    assert ps["is_confirmed_risk"] == 0
    assert ps["mitre_id"] == "T1046"


def test_masking_of_password_and_token():
    lines = _dump_lines(
        [
            {
                "timestamp": "2026-03-01T10:06:00Z",
                "flow_id": 800,
                "tx_id": 1,
                "event_type": "http",
                "http": {
                    "url": "/login?user=a&password=abc&token=xyz",
                    "status": 401,
                },
            },
            {
                "timestamp": "2026-03-01T10:06:00Z",
                "flow_id": 800,
                "tx_id": 1,
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "dest_port": 80,
                "alert": {"signature_id": 1000003, "signature": "Login attempt"},
            },
        ]
    )

    alerts, _ = parse_eve_lines(lines)
    assert len(alerts) == 1
    assert alerts[0]["raw_url"] == "/login?user=a&password=[MASKED]&token=[MASKED]"
    assert alerts[0]["pii_masked"] == 1
