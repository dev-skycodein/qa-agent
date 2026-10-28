"""python toolkit/engine/test_invariant_miner.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import invariant_miner as im  # noqa: E402


def _post(i, qty, stored=None, status="placed", method="POST", path="/orders"):
    body = {"id": i, "quantity": stored if stored is not None else qty, "status": status, "price": 10}
    return {"role": "user_a", "method": method, "path": path, "status": 201, "request": {"quantity": qty},
            "response": json.dumps(body)}


def test_mines_echo_enum_const_nonneg():
    log = [_post(i, qty=i % 5 + 1) for i in range(1, 21)]
    kinds = {(i["kind"], i["field"]) for i in im.mine(log)["invariants"]}
    assert ("echo", "quantity") in kinds and ("const", "status") in kinds and ("const", "price") in kinds
    assert ("nonneg", "quantity") in kinds and ("unique", "id") in kinds


def test_violation_found_on_held_out_part():
    log = [_post(i, qty=3) for i in range(1, 15)] + [_post(15, qty=3, stored=-3)]      # server stores -3 for 3
    v = im.mine(log)["violations"]
    assert any(x["kind"] == "echo" and x["field"] == "quantity" for x in v)
    assert any(x["kind"] == "nonneg" and x["field"] == "quantity" for x in v)


def test_clean_traffic_has_no_violations():
    assert im.mine([_post(i, qty=i % 4 + 1) for i in range(1, 25)])["violations"] == []


def test_too_little_data_mines_nothing_and_run_says_degraded():
    class Api:
        log = [_post(1, 1), _post(2, 2)]
    out = im.run(Api())
    assert out["status"] == "degraded" and out["findings"] == []


def test_truncated_bodies_are_counted_not_guessed():
    log = [{**_post(i, 1), "response": '{"id": 1, "quantity'} for i in range(20)]
    r = im.mine(log)
    assert r["invariants"] == [] and r["skipped_bodies"] == 20


def _item(i, name, req_name=None, method="GET", path="/items/1"):
    return {"role": "admin", "method": method, "path": path, "status": 200, "request": {"name": req_name} if req_name else None,
            "response": json.dumps({"id": i, "name": name, "label": "std"})}


def test_enum_over_values_the_run_sent_itself_is_not_mined():
    """Measured false positive: names created by our own fuzzing look like an enum on GET /items/{id}."""
    sends = [_item(100 + n, "x", req_name=v, method="POST", path="/items") for n, v in enumerate(["qa", "tee", "last-one"])]
    reads = [_item(i, "qa" if i % 2 else "tee") for i in range(1, 16)] + [_item(16, "last-one")]
    r = im.mine(sends + reads)
    assert not any(i["field"] == "name" and i["kind"] in ("enum", "const") for i in r["invariants"]), r["invariants"]
    assert r["violations"] == [] and r["client_controlled"] >= 1


def test_enum_over_values_the_server_chose_is_still_mined():
    sends = [_item(100, "x", req_name="whatever", method="POST", path="/items")]
    reads = [_item(i, "gold" if i % 2 else "silver") for i in range(1, 16)] + [_item(16, "bronze")]
    r = im.mine(sends + reads)
    assert any(i["field"] == "name" and i["kind"] == "enum" for i in r["invariants"])
    assert any(v["field"] == "name" and v["example"] == {"response": "bronze"} for v in r["violations"])


def test_long_bodies_are_read_from_the_body_key_not_the_300_char_response():
    def entry(i):
        body = json.dumps({"id": i, "status": "placed", "note": "n" * 600})
        return {"role": "u", "method": "POST", "path": "/orders", "status": 201, "request": {}, "response": body[:300], "body": body}
    r = im.mine([entry(i) for i in range(1, 21)])
    assert r["skipped_bodies"] == 0 and any(i["field"] == "status" and i["kind"] == "const" for i in r["invariants"])


def test_findings_are_info_only():
    class Api:
        log = [_post(i, qty=3) for i in range(1, 15)] + [_post(15, qty=3, stored=-3)]
    out = im.run(Api())
    assert out["findings"] and all(f["severity"] == "info" for f in out["findings"])


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print("FAIL", name, "-", type(exc).__name__, exc)
    sys.exit(1 if failed else 0)
