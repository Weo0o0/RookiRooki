import json
from backend.eve_parser import parse_eve

def write(path, events):
    path.write_text("\n".join(json.dumps(x) for x in events) + "\nnot json\n[]\n")

def alert(sid, flow=1, tx=1, url=None):
    x = {"event_type":"alert", "timestamp":"now", "flow_id":flow, "tx_id":tx, "alert":{"signature_id":sid,"signature":"password=secret"}}
    if url: x["http"] = {"url":url}
    return x

def test_filter_pair_escalate_and_mask(tmp_path):
    p = tmp_path / "eve.json"
    write(p, [alert(1000001), {"event_type":"http","flow_id":1,"tx_id":1,"http":{"status":200,"url":"/x?token=abc"}}, alert(9999)])
    rows, skipped = parse_eve(p)
    assert skipped == 2 and len(rows) == 1
    assert rows[0]["severity"] == "SEV1" and rows[0]["is_confirmed_risk"] == 1 and rows[0]["pii_masked"] == 1

def test_same_flow_does_not_use_other_request(tmp_path):
    p = tmp_path / "eve.json"
    write(p, [alert(1000001, tx=1), {"event_type":"http","flow_id":1,"tx_id":2,"http":{"status":200,"url":"/other"}}, {"event_type":"http","flow_id":1,"tx_id":1,"http":{"status":403,"url":"/attack"}}])
    assert parse_eve(p)[0][0]["severity"] == "SEV3"

def test_json_masking(tmp_path):
    p = tmp_path / "eve.json"
    write(p, [{"event_type":"alert", "alert":{"signature_id":1000002,"signature":"{\"password\": \"abc\"}"}}])
    rows, _ = parse_eve(p)
    assert rows[0]["signature"] == '{"password": "[MASKED]"}'
    assert rows[0]["pii_masked"] == 1

def test_status_rules_and_numeric_sid_and_bad_nested_fields(tmp_path):
    p = tmp_path / "eve.json"
    events = [
        {"event_type":"alert", "flow_id":1, "tx_id":1, "alert":{"signature_id":"1000001","signature":"s"}, "http": "bad"},
        {"event_type":"http", "flow_id":1, "tx_id":1, "http":{"status":404}},
        {"event_type":"alert", "flow_id":2, "alert":{"signature_id":1000003,"signature":"b"}},
        {"event_type":"alert", "flow_id":3, "alert":{"signature_id":1000004,"signature":"p"}},
        {"event_type":"http", "flow_id":2, "http":{"status":200}},
        {"event_type":"http", "flow_id":3, "http":{"status":200}},
    ]
    p.write_text("\n".join(json.dumps(x) for x in events))
    rows, _ = parse_eve(p)
    assert [(row["severity"], row["is_confirmed_risk"]) for row in rows] == [("SEV3", 0), ("SEV2", 0), ("SEV3", 0)]

def test_query_masking(tmp_path):
    p = tmp_path / "eve.json"
    write(p, [{"event_type":"alert", "http":{"url":"/login?user=a&password=abc&token=xyz"}, "alert":{"signature_id":1000001,"signature":"s"}}])
    assert parse_eve(p)[0][0]["raw_url"] == "/login?user=a&password=[MASKED]&token=[MASKED]"
