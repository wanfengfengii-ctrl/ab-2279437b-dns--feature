#!/usr/bin/env python3
"""One-shot API smoke test used by the Compose ``verify`` service.

It exercises the running API over HTTP only:

1. health endpoint,
2. a successful replay that crosses the 32-bit serial boundary (wraparound),
3. deterministic digest and canonical ordering,
4. an illegal log that must be rejected with a stable, change-located error
   code and must never leak a partial snapshot,
5. a rollback plan (``rollback_serials``) that is resubmitted against the
   forward records and must restore the starting zone step by step, plus
   rollback validation failures that must leak neither snapshot nor plan.

Exits 0 only when every assertion holds.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
WRAP = 1 << 32


def soa(serial: int) -> dict:
    return {
        "name": "example.com",
        "type": "SOA",
        "ttl": 3600,
        "mname": "ns1.example.com",
        "rname": "hostmaster.example.com",
        "serial": serial % WRAP,
        "refresh": 7200,
        "retry": 3600,
        "expire": 1209600,
        "minimum": 60,
    }


def a(name: str, address: str, ttl: int = 300) -> dict:
    return {"name": name, "type": "A", "ttl": ttl, "address": address}


def change(serial_from: int, serial_to: int, deletes=None, adds=None) -> dict:
    return {
        "deletes": [soa(serial_from), *(deletes or [])],
        "adds": [*(adds or []), soa(serial_to)],
    }


def request(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def check(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        print(f"FAIL: {label} {detail}".rstrip())
        sys.exit(1)
    print(f"PASS: {label}")


def canon(records) -> list:
    """Comparable canonical form of a record list, SOA serial blanked."""

    items = []
    for record in records:
        record = dict(record)
        if record.get("type") == "SOA":
            record["serial"] = None
        items.append(tuple(sorted(record.items())))
    return sorted(items)


def main() -> int:
    status, body = request("GET", "/healthz")
    check("healthz returns 200", status == 200 and body.get("status") == "ok")

    start = [
        soa(WRAP - 2),
        a("example.com", "192.0.2.1"),
        a("ns1.example.com", "192.0.2.10"),
    ]

    # --- Successful replay crossing the serial boundary ---------------------
    payload = {
        "start": start,
        "changes": [
            change(WRAP - 2, WRAP - 1, adds=[a("mail.example.com", "192.0.2.20")]),
            change(WRAP - 1, 0),
            change(0, 1),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", payload)
    check("wraparound replay returns 200", status == 200, str(body))
    check("final serial wrapped to 1", body.get("final_serial") == 1, str(body.get("final_serial")))
    check("all three changes applied", body.get("changes_applied") == 3)
    digest = body.get("sha256", "")
    check("sha256 digest present", len(digest) == 64 and all(c in "0123456789abcdef" for c in digest))

    records = body.get("records", [])
    keys = [(r["name"], r["type"]) for r in records]
    type_rank = {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}
    check("records are canonically sorted", keys == sorted(keys, key=lambda k: (k[0], type_rank[k[1]])))
    check("soa is at apex only", all(
        not (r["type"] == "SOA" and r["name"] != "example.com") for r in records
    ))
    check("added record visible", any(
        r["name"] == "mail.example.com" and r.get("address") == "192.0.2.20" for r in records
    ))

    # Replaying the identical payload yields the identical digest.
    status, body2 = request("POST", "/api/dns/ixfr/replay", payload)
    check("digest is deterministic", status == 200 and body2.get("sha256") == digest)
    check("no rollback plan without rollback_serials", "rollback_changes" not in body2)

    # --- Rollback plan: publishable inverse of the forward replay -----------
    rollback_payload = {
        "start": start,
        "changes": [
            change(WRAP - 2, WRAP - 1, adds=[a("mail.example.com", "192.0.2.20")]),
            change(WRAP - 1, 0),
            change(0, 1),
        ],
        "rollback_serials": [2, 3, 4],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", rollback_payload)
    check("rollback plan replay returns 200", status == 200, str(body))
    plan = body.get("rollback_changes")
    check("one rollback change per forward change", isinstance(plan, list) and len(plan) == 3)
    if not isinstance(plan, list) or len(plan) != 3:
        sys.exit(1)
    check("each rollback step opens and closes with an SOA", all(
        step["deletes"][0]["type"] == "SOA" and step["adds"][-1]["type"] == "SOA"
        for step in plan
    ))
    check("rollback step 1 opens with the forward final SOA",
          plan[0]["deletes"][0]["serial"] == 1, str(plan[0]["deletes"][0]))
    check("rollback serials close each step and chain into the next", (
        plan[0]["adds"][-1]["serial"] == 2
        and plan[1]["deletes"][0]["serial"] == 2
        and plan[1]["adds"][-1]["serial"] == 3
        and plan[2]["deletes"][0]["serial"] == 3
        and plan[2]["adds"][-1]["serial"] == 4
    ), str([step["adds"][-1]["serial"] for step in plan]))

    # Resubmitting the plan against the forward records restores the start
    # zone step by step (SOA serial excepted).
    status, step1 = request("POST", "/api/dns/ixfr/replay", {
        "start": body["records"], "changes": plan[:1],
    })
    status2, full = request("POST", "/api/dns/ixfr/replay", {
        "start": body["records"], "changes": plan,
    })
    check("rollback plan is replayable", status == 200 and status2 == 200,
          str(full)[:200])
    check("first rollback step restores serial 2", step1.get("final_serial") == 2)
    check("full rollback ends at last rollback serial", full.get("final_serial") == 4)
    check("full rollback restores the starting zone (serial excepted)",
          canon(full.get("records", [])) == canon(start))

    # Rollback serial that does not advance: stable error, no snapshot/plan.
    bad_rollback = dict(rollback_payload, rollback_serials=[2, 2, 4])
    status, body = request("POST", "/api/dns/ixfr/replay", bad_rollback)
    error = body.get("error", {})
    check("non-advancing rollback serial rejected with 422",
          status == 422 and error.get("code") == "ROLLBACK_SERIAL_NOT_ADVANCED", str(body))
    check("rollback error locates the 1-based step", error.get("rollback") == 2, str(error))
    check("no snapshot or partial plan on rollback error",
          set(body.keys()) == {"error"}, str(body.keys()))

    # Rollback serial count must match the number of changes.
    mismatched = dict(rollback_payload, rollback_serials=[2, 3])
    status, body = request("POST", "/api/dns/ixfr/replay", mismatched)
    error = body.get("error", {})
    check("rollback count mismatch rejected with 422",
          status == 422 and error.get("code") == "ROLLBACK_SERIALS_MISMATCH", str(body))
    check("count mismatch locates the 1-based step", error.get("rollback") == 3, str(error))
    check("no snapshot or partial plan on count mismatch",
          set(body.keys()) == {"error"}, str(body.keys()))

    # --- Illegal log: serial does not advance in change 2 -------------------
    bad = {
        "start": [soa(WRAP - 2), a("example.com", "192.0.2.1")],
        "changes": [
            change(WRAP - 2, WRAP - 1),
            change(WRAP - 1, WRAP - 1),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad)
    check("illegal log rejected with 422", status == 422, str(body))
    error = body.get("error", {})
    check("stable error code", error.get("code") == "SERIAL_NOT_ADVANCED", str(error))
    check("error locates the change (2)", error.get("change") == 2, str(error))
    check("error names the violated rule", bool(error.get("rule")))
    check("no partial snapshot leaked", set(body.keys()) == {"error"}, str(body.keys()))

    # --- Illegal log: delete misses an existing record ----------------------
    bad_delete = {
        "start": [soa(WRAP - 2)],
        "changes": [change(WRAP - 2, WRAP - 1, deletes=[a("ghost.example.com", "192.0.2.66")])],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad_delete)
    error = body.get("error", {})
    check("missing delete rejected", status == 422 and error.get("code") == "DELETE_NOT_FOUND", str(body))
    check("missing delete located to record 1", error.get("record") == 1)

    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
