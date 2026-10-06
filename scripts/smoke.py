#!/usr/bin/env python3
"""One-shot API smoke test used by the Compose ``verify`` service.

It exercises the running API over HTTP only:

1. health endpoint,
2. a successful replay that crosses the 32-bit serial boundary (wraparound),
3. deterministic digest and canonical ordering,
4. an illegal log that must be rejected with a stable, change-located error
   code and must never leak a partial snapshot,
5. the rollback plan: generated via ``rollback_serials``, structurally sound,
   and — when replayed from the forward records — restores the starting zone
   except for the SOA serial; invalid rollback serials are rejected with a
   stable error code and a 1-based step, again without any snapshot.

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


def canonical_without_serial(records) -> list:
    """Comparable record list with the SOA serial stripped out."""

    canon = []
    for record in records:
        record = dict(record)
        if record.get("type") == "SOA":
            record["serial"] = None
        canon.append(tuple(sorted(record.items())))
    return sorted(canon)


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

    # --- Rollback plan: generate, inspect, and replay it back ----------------
    rollback_start = [
        soa(WRAP - 2),
        a("example.com", "192.0.2.1"),
        a("ns1.example.com", "192.0.2.10"),
    ]
    forward_payload = {
        "start": rollback_start,
        "changes": [
            change(WRAP - 2, WRAP - 1, adds=[a("mail.example.com", "192.0.2.20")]),
            change(WRAP - 1, 0, deletes=[a("ns1.example.com", "192.0.2.10")]),
            change(0, 1),
        ],
        # One serial per change, in rollback order; each strictly advances.
        "rollback_serials": [2, 3, 4],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", forward_payload)
    check("rollback-enabled replay returns 200", status == 200, str(body))
    plan = body.get("rollback_changes")
    check(
        "rollback plan has one step per change",
        isinstance(plan, list) and len(plan) == 3,
        str(plan),
    )
    check(
        "first rollback step starts from the forward final SOA",
        plan[0]["deletes"][0]["type"] == "SOA" and plan[0]["deletes"][0]["serial"] == 1,
        str(plan[0]["deletes"][0]),
    )
    check(
        "each rollback step ends with the requested serial",
        all(
            step["adds"][-1]["type"] == "SOA" and step["adds"][-1]["serial"] == serial
            for step, serial in zip(plan, [2, 3, 4])
        ),
        str(plan),
    )
    check(
        "later rollback steps chain on the previous step's SOA",
        plan[1]["deletes"][0]["serial"] == 2 and plan[2]["deletes"][0]["serial"] == 3,
        str(plan),
    )

    # Replaying the plan from the forward records must restore the starting
    # zone — every canonical record and the SOA parameters, serial aside.
    status, rolled = request(
        "POST", "/api/dns/ixfr/replay", {"start": body["records"], "changes": plan}
    )
    check("rollback plan replays cleanly", status == 200, str(rolled))
    check("rollback ends at the last requested serial", rolled.get("final_serial") == 4)
    check(
        "rollback restores the starting zone (SOA serial aside)",
        canonical_without_serial(rolled.get("records", []))
        == canonical_without_serial(rollback_start),
    )

    # --- Rollback validation: stable codes, 1-based step, no snapshot --------
    status, body = request(
        "POST",
        "/api/dns/ixfr/replay",
        {
            "start": rollback_start,
            "changes": [change(WRAP - 2, WRAP - 1)],
            "rollback_serials": [2, 3],  # one serial too many
        },
    )
    error = body.get("error", {})
    check(
        "rollback count mismatch rejected",
        status == 422 and error.get("code") == "ROLLBACK_SERIALS_COUNT_MISMATCH",
        str(body),
    )
    check("count mismatch reports 1-based step", error.get("step") == 2, str(error))
    check("no snapshot or plan on rollback error", set(body.keys()) == {"error"})

    status, body = request(
        "POST",
        "/api/dns/ixfr/replay",
        {
            "start": rollback_start,
            "changes": [change(WRAP - 2, WRAP - 1), change(WRAP - 1, 0)],
            "rollback_serials": [5, 5],  # second serial does not advance
        },
    )
    error = body.get("error", {})
    check(
        "non-advancing rollback serial rejected",
        status == 422 and error.get("code") == "ROLLBACK_SERIAL_NOT_ADVANCED",
        str(body),
    )
    check("non-advancing serial located at step 2", error.get("step") == 2, str(error))
    check("still no snapshot or plan leaked", set(body.keys()) == {"error"})

    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
