"""Tests for the optional rollback plan (``rollback_serials``).

A legal plan, resubmitted to the same endpoint with the forward ``records``
as the starting zone, must restore every earlier zone version step by step —
ending at the original zone content with only the SOA serial moved on.
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
    ]


def _canon(records):
    """Comparable canonical form of a record list, SOA serial blanked."""

    items = []
    for record in records:
        record = dict(record)
        if record["type"] == "SOA":
            record["serial"] = None
        items.append(tuple(sorted(record.items())))
    return sorted(items)


def _soa_of(records):
    return next(r for r in records if r["type"] == "SOA")


# ---------------------------------------------------------------------------
# Happy paths: plan shape and round-trip restoration
# ---------------------------------------------------------------------------


def test_rollback_plan_shape_and_roundtrip():
    start = _start()
    changes = [
        change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")]),
        change(101, 102, deletes=[rr("www.example.com", "CNAME", 300, target="example.com")]),
        change(102, 103, adds=[rr("example.com", "TXT", 300, text="v=spf1 -all")]),
    ]
    result = replay({"start": start, "changes": changes, "rollback_serials": [201, 202, 203]})
    assert result["final_serial"] == 103

    plan = result["rollback_changes"]
    assert len(plan) == 3
    for step in plan:
        assert step["deletes"][0]["type"] == "SOA"
        assert step["adds"][-1]["type"] == "SOA"

    # Step 1 opens with the forward final SOA; every step closes with the
    # prescribed rollback serial, which the next step then opens with.
    assert plan[0]["deletes"][0]["serial"] == 103
    assert plan[0]["adds"][-1]["serial"] == 201
    assert plan[1]["deletes"][0]["serial"] == 201
    assert plan[1]["adds"][-1]["serial"] == 202
    assert plan[2]["deletes"][0]["serial"] == 202
    assert plan[2]["adds"][-1]["serial"] == 203

    # Resubmitting the plan against the forward snapshot restores the start
    # zone exactly, except the SOA serial ends at the last rollback serial.
    back = replay({"start": result["records"], "changes": plan})
    assert back["final_serial"] == 203
    assert _canon(back["records"]) == _canon(start)
    assert _soa_of(back["records"])["serial"] == 203


def test_rollback_plan_restores_step_by_step():
    start = _start()
    changes = [
        change(100, 101, adds=[rr("a.example.com", "A", 300, address="192.0.2.5")]),
        change(
            101,
            102,
            deletes=[rr("a.example.com", "A", 300, address="192.0.2.5")],
            adds=[rr("b.example.com", "A", 300, address="192.0.2.6")],
        ),
    ]
    forward = replay({"start": start, "changes": changes, "rollback_serials": [300, 301]})
    plan = forward["rollback_changes"]

    # After the first rollback step the zone equals the state after change 1.
    mid = replay({"start": forward["records"], "changes": plan[:1]})
    expected_mid = replay({"start": start, "changes": changes[:1]})
    assert mid["final_serial"] == 300
    assert _canon(mid["records"]) == _canon(expected_mid["records"])

    # After both steps the zone is the start zone again (serial aside).
    end = replay({"start": forward["records"], "changes": plan})
    assert end["final_serial"] == 301
    assert _canon(end["records"]) == _canon(start)


def test_rollback_plan_inverts_each_change_in_reverse_order():
    changes = [
        change(
            100,
            101,
            deletes=[rr("ns1.example.com", "A", 300, address="192.0.2.10")],
            adds=[
                rr("ns1.example.com", "A", 600, address="192.0.2.10"),
                rr("ns1.example.com", "A", 600, address="192.0.2.11"),
            ],
        ),
        change(101, 102, adds=[rr("txt.example.com", "TXT", 300, text="hello")]),
    ]
    result = replay({"start": _start(), "changes": changes, "rollback_serials": [700, 701]})
    plan = result["rollback_changes"]

    # Step 1 undoes change 2: the TXT add becomes a delete.
    assert [r["text"] for r in plan[0]["deletes"] if r["type"] == "TXT"] == ["hello"]
    assert [r for r in plan[0]["adds"] if r["type"] != "SOA"] == []

    # Step 2 undoes change 1: the two 600-TTL adds are deleted, the 300-TTL
    # record is re-added.
    a_deletes = [r for r in plan[1]["deletes"] if r["type"] == "A"]
    assert {(r["ttl"], r["address"]) for r in a_deletes} == {
        (600, "192.0.2.10"),
        (600, "192.0.2.11"),
    }
    a_adds = [r for r in plan[1]["adds"] if r["type"] == "A"]
    assert [(r["ttl"], r["address"]) for r in a_adds] == [(300, "192.0.2.10")]


def test_rollback_restores_historical_soa_parameters():
    start = _start()
    promoted_soa = soa(101, ttl=7200, mname="ns2.example.com", refresh=4000, minimum=120)
    changes = [{"deletes": [soa(100)], "adds": [promoted_soa]}]
    result = replay({"start": start, "changes": changes, "rollback_serials": [500]})

    closing = result["rollback_changes"][0]["adds"][-1]
    assert closing["type"] == "SOA"
    assert closing["serial"] == 500
    # Historical parameters and TTL, not the promoted ones.
    assert closing["ttl"] == 3600
    assert closing["mname"] == "ns1.example.com"
    assert closing["refresh"] == 7200
    assert closing["minimum"] == 60

    back = replay({"start": result["records"], "changes": result["rollback_changes"]})
    assert _canon(back["records"]) == _canon(start)


def test_rollback_serials_may_wraparound():
    start = [soa(SERIAL_MOD - 2), rr("example.com", "A", 300, address="192.0.2.1")]
    changes = [change(SERIAL_MOD - 2, SERIAL_MOD - 1), change(SERIAL_MOD - 1, 0)]
    result = replay({"start": start, "changes": changes, "rollback_serials": [1, 2]})
    back = replay({"start": result["records"], "changes": result["rollback_changes"]})
    assert back["final_serial"] == 2
    assert _canon(back["records"]) == _canon(start)


def test_omitted_rollback_serials_keeps_response_shape():
    result = replay({"start": _start(), "changes": [change(100, 101)]})
    assert "rollback_changes" not in result
    assert set(result) == {"apex", "final_serial", "changes_applied", "records", "sha256"}


# ---------------------------------------------------------------------------
# rollback_serials validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "serials,step",
    [
        ([], 1),               # missing from the very first step
        ([201], 2),            # too short
        ([201, 202, 203, 204], 4),  # too long
    ],
)
def test_rollback_serials_count_mismatch(serials, step):
    changes = [change(100, 101), change(101, 102), change(102, 103)]
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": changes, "rollback_serials": serials})
    assert exc.value.code == "ROLLBACK_SERIALS_MISMATCH"
    assert exc.value.rollback == step


def test_rollback_serial_must_advance_from_forward_final_serial():
    changes = [change(100, 101), change(101, 102)]
    for bad_first in (102, 101, 50):  # equal, behind, far behind
        with pytest.raises(ReplayError) as exc:
            replay({"start": _start(), "changes": changes, "rollback_serials": [bad_first, 300]})
        assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
        assert exc.value.rollback == 1


def test_rollback_serials_must_advance_step_by_step():
    changes = [change(100, 101), change(101, 102), change(102, 103)]
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": changes, "rollback_serials": [200, 200, 300]})
    assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert exc.value.rollback == 2
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": changes, "rollback_serials": [200, 300, 250]})
    assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert exc.value.rollback == 3


def test_rollback_serial_wraparound_too_far_rejected():
    # 2^31 ahead of the final serial is exactly halfway: not "after".
    changes = [change(100, 101)]
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": changes, "rollback_serials": [101 + (1 << 31)]})
    assert exc.value.code == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert exc.value.rollback == 1


@pytest.mark.parametrize("bad", [-1, SERIAL_MOD, "101", 1.5, True, None])
def test_rollback_serial_entry_must_be_uint32(bad):
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": [change(100, 101)], "rollback_serials": [bad]})
    assert exc.value.code == "REQUEST_MALFORMED"
    assert exc.value.rule == "rollback_serial_must_be_uint32"
    assert exc.value.rollback == 1


def test_rollback_serials_must_be_array():
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": [change(100, 101)], "rollback_serials": "soon"})
    assert exc.value.code == "REQUEST_MALFORMED"
    assert exc.value.rule == "rollback_serials_must_be_array"


def test_forward_error_still_reported_when_rollback_requested():
    with pytest.raises(ReplayError) as exc:
        replay({"start": _start(), "changes": [change(100, 100)], "rollback_serials": [200]})
    assert exc.value.code == "SERIAL_NOT_ADVANCED"
    assert exc.value.change == 1


# ---------------------------------------------------------------------------
# HTTP level
# ---------------------------------------------------------------------------


def test_api_rollback_plan_smoke():
    body = {
        "start": _start(),
        "changes": [
            change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")]),
            change(101, 102),
        ],
        "rollback_serials": [900, 901],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200
    data = response.json()
    assert data["final_serial"] == 102
    plan = data["rollback_changes"]
    assert len(plan) == 2

    # The plan is publishable as-is against the forward records.
    back = client.post("/api/dns/ixfr/replay", json={"start": data["records"], "changes": plan})
    assert back.status_code == 200, back.text
    assert back.json()["final_serial"] == 901
    assert _canon(back.json()["records"]) == _canon(_start())


def test_api_rollback_error_returns_no_snapshot_or_partial_plan():
    body = {
        "start": _start(),
        "changes": [change(100, 101)],
        "rollback_serials": [101],  # equal to the forward final serial
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    payload = response.json()
    assert set(payload.keys()) == {"error"}
    error = payload["error"]
    assert error["code"] == "ROLLBACK_SERIAL_NOT_ADVANCED"
    assert error["rule"] == "rollback_serial_must_advance_per_rfc1982"
    assert error["rollback"] == 1


def test_api_rollback_count_mismatch():
    body = {
        "start": _start(),
        "changes": [change(100, 101)],
        "rollback_serials": [200, 201],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    payload = response.json()
    assert set(payload.keys()) == {"error"}
    error = payload["error"]
    assert error["code"] == "ROLLBACK_SERIALS_MISMATCH"
    assert error["rollback"] == 2


def test_api_omitted_rollback_serials_leaves_response_unchanged():
    body = {"start": _start(), "changes": [change(100, 101)]}
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200
    assert "rollback_changes" not in response.json()
