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
