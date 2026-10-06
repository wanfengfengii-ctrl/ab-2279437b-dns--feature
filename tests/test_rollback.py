"""Tests for the optional rollback plan (``rollback_serials``) feature.

The plan must invert the forward log change by change, in reverse order, keep
SOA serials advancing per RFC 1982, and — when replayed from the forward
snapshot — restore the starting zone except for the SOA serial.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.engine import SERIAL_MOD, ReplayError, replay

from .conftest import change, rr, soa

client = TestClient(app)


def _start():
    return [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
        rr("example.com", "TXT", 300, text="v=spf1 -all"),
    ]


def _canonical(records):
    """Comparable record list with the SOA serial stripped out."""

    canon = []
    for record in records:
        record = dict(record)
        if record["type"] == "SOA":
            record["serial"] = None
        canon.append(tuple(sorted(record.items())))
    return sorted(canon)


# ---------------------------------------------------------------------------
# Plan generation and structure
# ---------------------------------------------------------------------------


def test_omitted_rollback_serials_keeps_response_unchanged():
    result = replay({"start": _start(), "changes": [change(100, 101)]})
    assert set(result.keys()) == {
        "apex",
        "final_serial",
        "changes_applied",
        "records",
        "sha256",
    }


def test_rollback_plan_inverts_changes_in_reverse_order():
    changes = [
        change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")]),
        change(
            101,
            102,
            deletes=[rr("www.example.com", "CNAME", 300, target="example.com")],
            adds=[rr("www.example.com", "A", 300, address="192.0.2.80")],
        ),
    ]
    result = replay(
        {"start": _start(), "changes": changes, "rollback_serials": [201, 202]}
    )
    plan = result["rollback_changes"]
    assert len(plan) == 2

    # Step 1 undoes change 2: current SOA is the forward final one (102).
    assert plan[0]["deletes"][0]["type"] == "SOA"
    assert plan[0]["deletes"][0]["serial"] == 102
    # The A record added by change 2 is removed, the CNAME it deleted returns.
    assert {r["type"] for r in plan[0]["deletes"][1:]} == {"A"}
    assert plan[0]["deletes"][1]["name"] == "www.example.com"
    assert {r["type"] for r in plan[0]["adds"][:-1]} == {"CNAME"}
    assert plan[0]["adds"][0]["target"] == "example.com"
    # ... and the step ends with the requested new serial.
    assert plan[0]["adds"][-1]["type"] == "SOA"
    assert plan[0]["adds"][-1]["serial"] == 201

    # Step 2 undoes change 1, starting from the SOA published by step 1.
    assert plan[1]["deletes"][0]["type"] == "SOA"
    assert plan[1]["deletes"][0]["serial"] == 201
    assert [r["name"] for r in plan[1]["deletes"][1:]] == ["mail.example.com"]
    assert plan[1]["adds"][-1]["serial"] == 202


def test_rollback_restores_historical_soa_parameters():
    start = [soa(100, refresh=1000), rr("example.com", "A", 300, address="192.0.2.1")]
    changes = [
        {"deletes": [soa(100, refresh=1000)], "adds": [soa(101, refresh=2000)]},
        {"deletes": [soa(101, refresh=2000)], "adds": [soa(102, refresh=3000)]},
    ]
    result = replay(
        {"start": start, "changes": changes, "rollback_serials": [500, 600]}
    )
    plan = result["rollback_changes"]

    # Step 1 undoes the second change: delete SOA(refresh=3000, serial 102),
    # publish the historical parameters (refresh=2000) with the new serial.
    assert plan[0]["deletes"][0]["serial"] == 102
    assert plan[0]["deletes"][0]["refresh"] == 3000
    assert plan[0]["adds"][-1]["serial"] == 500
    assert plan[0]["adds"][-1]["refresh"] == 2000

    # Step 2 starts from the SOA published by step 1 and restores the
    # starting zone's SOA parameters under the second rollback serial.
    assert plan[1]["deletes"][0]["serial"] == 500
    assert plan[1]["deletes"][0]["refresh"] == 2000
    assert plan[1]["adds"][-1]["serial"] == 600
    assert plan[1]["adds"][-1]["refresh"] == 1000


# ---------------------------------------------------------------------------
# Round trips: replaying the plan from the forward records walks the zone back
# ---------------------------------------------------------------------------


def test_rollback_round_trip_restores_start_zone_except_serial():
    start = _start()
    changes = [
        change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")]),
        change(
            101,
            102,
            deletes=[rr("www.example.com", "CNAME", 300, target="example.com")],
            adds=[rr("www.example.com", "A", 300, address="192.0.2.80")],
        ),
        change(102, 103, deletes=[rr("example.com", "TXT", 300, text="v=spf1 -all")]),
    ]
    forward = replay(
        {"start": start, "changes": changes, "rollback_serials": [201, 202, 203]}
    )
    assert forward["final_serial"] == 103

    rolled = replay({"start": forward["records"], "changes": forward["rollback_changes"]})
    assert rolled["final_serial"] == 203
    assert _canonical(rolled["records"]) == _canonical(start)


def test_rollback_restores_each_intermediate_state_step_by_step():
    start = _start()
    changes = [
        change(100, 101, adds=[rr("a.example.com", "A", 300, address="192.0.2.5")]),
        change(101, 102, adds=[rr("b.example.com", "A", 300, address="192.0.2.6")]),
        change(102, 103, deletes=[rr("a.example.com", "A", 300, address="192.0.2.5")]),
    ]
    forward = replay(
        {"start": start, "changes": changes, "rollback_serials": [201, 202, 203]}
    )

    # Canonical forward states after 0..3 changes (SOA serial stripped).
    states = [_canonical(start)]
    for i in range(1, 4):
        states.append(
            _canonical(replay({"start": start, "changes": changes[:i]})["records"])
        )

    records = forward["records"]
    for i, step in enumerate(forward["rollback_changes"], start=1):
        records = replay({"start": records, "changes": [step]})["records"]
        assert _canonical(records) == states[len(states) - 1 - i]


def test_rollback_handles_ttl_and_cname_swaps():
    start = [
        soa(100),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
    ]
    changes = [
        # TTL change via full RRset replacement.
        change(
            100,
            101,
            deletes=[rr("ns1.example.com", "A", 300, address="192.0.2.10")],
            adds=[rr("ns1.example.com", "A", 600, address="192.0.2.10")],
        ),
        # CNAME swapped for an A record at the same owner name.
        change(
            101,
            102,
            deletes=[rr("www.example.com", "CNAME", 300, target="example.com")],
            adds=[rr("www.example.com", "A", 300, address="192.0.2.80")],
        ),
    ]
    forward = replay(
        {"start": start, "changes": changes, "rollback_serials": [301, 302]}
    )
    rolled = replay({"start": forward["records"], "changes": forward["rollback_changes"]})
    assert _canonical(rolled["records"]) == _canonical(start)


def test_rollback_serials_may_wraparound():
    start = [soa(SERIAL_MOD - 2), rr("example.com", "A", 300, address="192.0.2.1")]
    changes = [
        change(SERIAL_MOD - 2, SERIAL_MOD - 1, adds=[rr("m.example.com", "A", 300, address="192.0.2.20")]),
        change(SERIAL_MOD - 1, 0),
    ]
    # 0 -> 2^32-1 -> 1 would go backwards; 0 -> 1 -> 2 advances normally, and
    # serials right at the boundary wrap: 2^32-2 -> 2^32-1 -> 0 also advances.
    forward = replay(
        {
            "start": start,
            "changes": changes,
            "rollback_serials": [1, 2],
        }
    )
    rolled = replay({"start": forward["records"], "changes": forward["rollback_changes"]})
    assert rolled["final_serial"] == 2
    assert _canonical(rolled["records"]) == _canonical(start)

    forward = replay(
        {
            "start": [soa(SERIAL_MOD - 3), rr("example.com", "A", 300, address="192.0.2.1")],
            "changes": [change(SERIAL_MOD - 3, SERIAL_MOD - 2)],
            "rollback_serials": [SERIAL_MOD - 1],
        }
    )
    assert forward["rollback_changes"][0]["adds"][-1]["serial"] == SERIAL_MOD - 1


# ---------------------------------------------------------------------------
# rollback_serials validation: stable codes and 1-based step, never a snapshot
# ---------------------------------------------------------------------------


def test_rollback_serials_count_mismatch_too_few():
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101), change(101, 102)],
                "rollback_serials": [201],
            }
        )
    assert exc.value.code == "ROLLBACK_SERIALS_COUNT_MISMATCH"
    assert exc.value.step == 2  # first step without a serial


def test_rollback_serials_count_mismatch_too_many():
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101)],
                "rollback_serials": [201, 202],
            }
        )
    assert exc.value.code == "ROLLBACK_SERIALS_COUNT_MISMATCH"
    assert exc.value.step == 2  # first serial without a change


def test_rollback_first_serial_must_advance_from_forward_final():
    for serial in (103, 102, 50):  # equal to final, one behind, far behind
        with pytest.raises(ReplayError) as exc:
            replay(
                {
                    "start": _start(),
                    "changes": [change(100, 101), change(101, 103)],
                    "rollback_serials": [serial, 900],
                }
            )
        assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
        assert exc.value.step == 1


def test_rollback_later_serial_must_advance_from_previous():
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101), change(101, 102)],
                "rollback_serials": [200, 200],
            }
        )
    assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert exc.value.step == 2

    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101), change(101, 102)],
                "rollback_serials": [200, 150],
            }
        )
    assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert exc.value.step == 2


def test_rollback_serial_advancement_uses_rfc1982_wraparound():
    # From final serial 2^32-2, 2^32-1 and then 0 are valid forward steps.
    start = [soa(SERIAL_MOD - 3), rr("example.com", "A", 300, address="192.0.2.1")]
    result = replay(
        {
            "start": start,
            "changes": [change(SERIAL_MOD - 3, SERIAL_MOD - 2)],
            "rollback_serials": [SERIAL_MOD - 1],
        }
    )
    assert result["rollback_changes"][0]["adds"][-1]["serial"] == SERIAL_MOD - 1

    # Exactly half the serial space ahead is *not* an advance.
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101)],
                "rollback_serials": [(101 + (1 << 31)) % SERIAL_MOD],
            }
        )
    assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert exc.value.step == 1


@pytest.mark.parametrize("bad", [-1, SERIAL_MOD, 1.5, "201", True, None])
def test_rollback_serial_must_be_uint32(bad):
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101), change(101, 102)],
                "rollback_serials": [201, bad],
            }
        )
    assert exc.value.code == "ROLLBACK_SERIAL_INVALID"
    assert exc.value.step == 2


def test_rollback_serials_must_be_an_array():
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 101)],
                "rollback_serials": "201",
            }
        )
    assert exc.value.code == "REQUEST_MALFORMED"


def test_forward_failure_takes_precedence_over_rollback_validation():
    # The forward log is broken *and* the rollback serials are short: the
    # forward error is reported, exactly as without the rollback option.
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": [change(100, 100)],
                "rollback_serials": [],
            }
        )
    assert exc.value.code == "SERIAL_NOT_ADVANCED"
    assert exc.value.change == 1


# ---------------------------------------------------------------------------
# HTTP level
# ---------------------------------------------------------------------------


def test_api_rollback_success_envelope():
    body = {
        "start": _start(),
        "changes": [change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")])],
        "rollback_serials": [555],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["final_serial"] == 101
    assert len(data["rollback_changes"]) == 1
    step = data["rollback_changes"][0]
    assert step["deletes"][0]["serial"] == 101
    assert step["adds"][-1]["serial"] == 555


def test_api_rollback_round_trip_over_http():
    start = _start()
    forward = client.post(
        "/api/dns/ixfr/replay",
        json={
            "start": start,
            "changes": [
                change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")]),
                change(101, 102, deletes=[rr("ns1.example.com", "A", 300, address="192.0.2.10")]),
            ],
            "rollback_serials": [700, 701],
        },
    )
    assert forward.status_code == 200, forward.text
    plan = forward.json()["rollback_changes"]

    rolled = client.post(
        "/api/dns/ixfr/replay",
        json={"start": forward.json()["records"], "changes": plan},
    )
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["final_serial"] == 701
    assert _canonical(rolled.json()["records"]) == _canonical(start)


def test_api_rollback_error_never_returns_snapshot_or_plan():
    body = {
        "start": _start(),
        "changes": [change(100, 101)],
        "rollback_serials": [101],  # does not advance from the final serial
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    payload = response.json()
    assert set(payload.keys()) == {"error"}
    error = payload["error"]
    assert error["code"] == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert error["step"] == 1
    assert error["rule"] == "rollback_serial_must_advance_per_rfc1982"


def test_api_rollback_count_mismatch_error():
    body = {
        "start": _start(),
        "changes": [change(100, 101), change(101, 102)],
        "rollback_serials": [201],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    payload = response.json()
    assert set(payload.keys()) == {"error"}
    assert payload["error"]["code"] == "ROLLBACK_SERIALS_COUNT_MISMATCH"
    assert payload["error"]["step"] == 2
