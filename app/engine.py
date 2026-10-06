"""Offline IXFR replay engine.

The engine is deliberately free of any web framework dependency: it takes a
plain request payload (``dict``) and either returns the final, canonical zone
snapshot or raises :class:`ReplayError` carrying a *stable* error code that
pinpoints the offending change (1-based; ``0`` denotes the starting zone).

Rules implemented:

* Every change starts by deleting the current SOA and ends by adding a single,
  unique new SOA whose serial strictly advances per RFC 1982 serial arithmetic
  (32-bit, including wraparound).
* Every delete must hit an existing, identical RR (name/type/TTL/rdata).
* Every add must neither duplicate an existing RR nor another add in the same
  change; an RRset keeps one TTL.
* CNAME never coexists with any other data at the same owner name.
* The apex always holds exactly one SOA.
* A failing change — and therefore the whole replay — never produces a partial
  snapshot: each change is applied to a private copy first.

Optionally the caller may attach ``rollback_serials`` — one 32-bit serial per
forward change, in rollback order. The first must strictly advance from the
forward final serial and each subsequent one from the previous rollback
serial, per the same RFC 1982 rules. The response then also carries
``rollback_changes``: the forward changes inverted in reverse order, each
opening with the SOA live at that rollback moment and closing with the
historical SOA parameters carrying the prescribed new serial. Resubmitting
that plan against the forward ``records`` restores every previous zone
version step by step (the SOA serial ends at the last rollback serial).
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any

SERIAL_MOD = 1 << 32
SERIAL_HALF = 1 << 31
MAX_TTL = (1 << 31) - 1
MAX_RECORDS = 5000
MAX_CHANGES = 64

RTYPES = ("SOA", "A", "AAAA", "CNAME", "TXT")
RTYPE_ORDER = {rtype: index for index, rtype in enumerate(RTYPES)}

_LABEL_RE = re.compile(r"^(?:\*|[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)$")


class ReplayError(Exception):
    """Validation failure with a stable machine-readable code."""

    def __init__(
        self,
        code: str,
        rule: str,
        change: int = 0,
        message: str = "",
        *,
        record: int | None = None,
        field: str | None = None,
        rollback: int | None = None,
    ) -> None:
        super().__init__(message or rule)
        self.code = code
        self.rule = rule
        self.change = change
        self.message = message or rule
        self.record = record
        self.field = field
        self.rollback = rollback

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "rule": self.rule,
            "change": self.change,
            "message": self.message,
        }
        if self.record is not None:
            payload["record"] = self.record
        if self.field is not None:
            payload["field"] = self.field
        if self.rollback is not None:
            payload["rollback"] = self.rollback
        return payload


@dataclass
class RRset:
    ttl: int
    rdatas: set[tuple[Any, ...]] = field(default_factory=set)


@dataclass
class Record:
    name: str
    rtype: str
    ttl: int
    rdata: tuple[Any, ...]

    def identity(self) -> tuple[Any, ...]:
        return (self.name, self.rtype, self.ttl, *self.rdata)


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def normalize_name(value: Any, change: int, field_name: str = "name") -> str:
    """DNS names are compared case-insensitively; canonicalize to lowercase.

    A single trailing dot (absolute form) is accepted and stripped so that
    ``Example.COM.`` and ``example.com`` denote the same owner.
    """

    if not isinstance(value, str):
        raise ReplayError(
            "INVALID_RECORD", "field_must_be_string", change, field=field_name
        )
    name = value
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253:
        raise ReplayError(
            "INVALID_RECORD", "invalid_name_length", change, field=field_name
        )
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63 or not _LABEL_RE.match(label):
            raise ReplayError(
                "INVALID_RECORD", "invalid_name_label", change, field=field_name
            )
    return name.lower()


def _uint(value: Any, field_name: str, change: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReplayError(
            "INVALID_RECORD", "field_must_be_integer", change, field=field_name
        )
    if not 0 <= value <= maximum:
        raise ReplayError(
            "INVALID_RECORD", "field_out_of_range", change, field=field_name
        )
    return value


def _ttl(value: Any, change: int) -> int:
    return _uint(value, "ttl", change, MAX_TTL)


def normalize_record(raw: Any, change: int, index: int | None = None) -> Record:
    if not isinstance(raw, dict):
        raise ReplayError("INVALID_RECORD", "record_must_be_object", change)
    rtype = raw.get("type")
    if not isinstance(rtype, str) or rtype.upper() not in RTYPE_ORDER:
        raise ReplayError(
            "INVALID_RECORD",
            "unsupported_rtype",
            change,
            field="type",
            record=index if index is not None else -1,
        )
    rtype = rtype.upper()
    name = normalize_name(raw.get("name"), change)
    ttl = _ttl(raw.get("ttl"), change)

    def need_string(field_name: str) -> str:
        value = raw.get(field_name)
        if not isinstance(value, str):
            raise ReplayError(
                "INVALID_RECORD", "field_must_be_string", change, field=field_name
            )
        return value

    if rtype == "SOA":
        rdata = (
            normalize_name(raw.get("mname"), change, "mname"),
            normalize_name(raw.get("rname"), change, "rname"),
            _uint(raw.get("serial"), "serial", change, SERIAL_MOD - 1),
            _uint(raw.get("refresh"), "refresh", change, MAX_TTL),
            _uint(raw.get("retry"), "retry", change, MAX_TTL),
            _uint(raw.get("expire"), "expire", change, MAX_TTL),
            _uint(raw.get("minimum"), "minimum", change, MAX_TTL),
        )
    elif rtype == "A":
        address = need_string("address")
        try:
            rdata = (str(IPv4Address(address)),)
        except (AddressValueError, ValueError):
            raise ReplayError(
                "INVALID_RECORD", "invalid_ipv4_address", change, field="address"
            )
    elif rtype == "AAAA":
        address = need_string("address")
        try:
            rdata = (str(IPv6Address(address)).lower(),)
        except (AddressValueError, ValueError):
            raise ReplayError(
                "INVALID_RECORD", "invalid_ipv6_address", change, field="address"
            )
    elif rtype == "CNAME":
        rdata = (normalize_name(raw.get("target"), change, "target"),)
    else:  # TXT — character strings are case sensitive in the DNS.
        rdata = (need_string("text"),)

    return Record(name=name, rtype=rtype, ttl=ttl, rdata=rdata)


# ---------------------------------------------------------------------------
# Serial arithmetic (RFC 1982)
# ---------------------------------------------------------------------------


def serial_advances(old: int, new: int) -> bool:
    """True iff ``new`` is strictly after ``old`` in 32-bit serial space."""

    if old == new:
        return False
    return 0 < (new - old) % SERIAL_MOD < SERIAL_HALF


# ---------------------------------------------------------------------------
# Zone mutation, with all invariants enforced
# ---------------------------------------------------------------------------


def _record_existing(zone: dict[tuple[str, str], RRset], record: Record) -> bool:
    rrset = zone.get((record.name, record.rtype))
    return rrset is not None and rrset.ttl == record.ttl and record.rdata in rrset.rdatas


def _delete(
    zone: dict[tuple[str, str], RRset], record: Record, change: int, index: int
) -> None:
    rrset = zone.get((record.name, record.rtype))
    if rrset is None or record.rdata not in rrset.rdatas:
        raise ReplayError(
            "DELETE_NOT_FOUND",
            "delete_must_hit_existing_record",
            change,
            record=index,
        )
    if rrset.ttl != record.ttl:
        # Same name/type/rdata but a different TTL is not the same RR.
        raise ReplayError(
            "DELETE_NOT_FOUND",
            "delete_ttl_mismatch",
            change,
            record=index,
        )
    rrset.rdatas.remove(record.rdata)
    if not rrset.rdatas:
        del zone[(record.name, record.rtype)]


def _add(
    zone: dict[tuple[str, str], RRset], record: Record, change: int, index: int
) -> None:
    key = (record.name, record.rtype)
    rrset = zone.get(key)

    if record.rtype == "CNAME":
        for other_type in _types_at(zone, record.name):
            # Every other type at the same owner is a hard conflict, and a
            # second *distinct* CNAME target is a coexistence violation too;
            # an identical duplicate CNAME is reported below as a duplicate.
            if other_type != "CNAME":
                raise ReplayError(
                    "CNAME_CONFLICT",
                    "cname_cannot_coexist",
                    change,
                    record=index,
                )
        existing_cname = zone.get(key)
        if (
            existing_cname is not None
            and record.rdata not in existing_cname.rdatas
        ):
            raise ReplayError(
                "CNAME_CONFLICT",
                "cname_cannot_coexist",
                change,
                record=index,
            )
    else:
        if (record.name, "CNAME") in zone:
            raise ReplayError(
                "CNAME_CONFLICT",
                "cname_cannot_coexist",
                change,
                record=index,
            )

    if rrset is not None:
        if rrset.ttl != record.ttl:
            raise ReplayError(
                "TTL_MISMATCH",
                "rrset_ttl_must_be_consistent",
                change,
                record=index,
            )
        if record.rdata in rrset.rdatas:
            raise ReplayError(
                "RECORD_DUPLICATE",
                "add_must_not_duplicate",
                change,
                record=index,
            )
        rrset.rdatas.add(record.rdata)
    else:
        zone[key] = RRset(ttl=record.ttl, rdatas={record.rdata})


def _types_at(zone: dict[tuple[str, str], RRset], name: str) -> set[str]:
    return {rtype for (owner, rtype) in zone if owner == name}


# ---------------------------------------------------------------------------
# Request envelope validation
# ---------------------------------------------------------------------------


def _records_list(value: Any, change: int, key: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReplayError(
            "INVALID_CHANGE", f"{key}_must_be_array", change, field=key
        )
    return value


def _rollback_serials(payload: dict[str, Any], change_count: int) -> list[int] | None:
    """Validate the optional ``rollback_serials`` request member.

    Returns ``None`` when the member is absent (legacy behaviour) or the
    validated list of 32-bit serials — exactly one per forward change, in
    rollback order. Count mismatches are reported at the first 1-based
    rollback step where the two lists disagree.
    """

    if "rollback_serials" not in payload:
        return None
    value = payload["rollback_serials"]
    if not isinstance(value, list):
        raise ReplayError(
            "REQUEST_MALFORMED",
            "rollback_serials_must_be_array",
            field="rollback_serials",
        )
    if len(value) != change_count:
        raise ReplayError(
            "ROLLBACK_SERIALS_MISMATCH",
            "rollback_serials_count_must_match_changes",
            rollback=min(len(value), change_count) + 1,
        )
    serials: list[int] = []
    for step, entry in enumerate(value, start=1):
        if (
            isinstance(entry, bool)
            or not isinstance(entry, int)
            or not 0 <= entry < SERIAL_MOD
        ):
            raise ReplayError(
                "REQUEST_MALFORMED",
                "rollback_serial_must_be_uint32",
                field="rollback_serials",
                rollback=step,
            )
        serials.append(entry)
    return serials


def _name_in_zone(name: str, apex: str) -> bool:
    return name == apex or name.endswith("." + apex)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def replay(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ReplayError("REQUEST_MALFORMED", "payload_must_be_object")

    start = payload.get("start")
    if not isinstance(start, list) or not start:
        raise ReplayError(
            "REQUEST_MALFORMED", "start_must_be_nonempty_array", field="start"
        )
    changes = payload.get("changes")
    if not isinstance(changes, list) or not (1 <= len(changes) <= MAX_CHANGES):
        raise ReplayError(
            "REQUEST_MALFORMED",
            "changes_count_out_of_range",
            field="changes",
        )

    total_records = len(start) + sum(
        len(_records_list(change.get("deletes"), index + 1, "deletes"))
        + len(_records_list(change.get("adds"), index + 1, "adds"))
        for index, change in enumerate(changes)
        if isinstance(change, dict)
    )
    if total_records > MAX_RECORDS:
        raise ReplayError(
            "REQUEST_LIMIT", "record_count_exceeds_5000", field="records"
        )

    rollback_serials = _rollback_serials(payload, len(changes))

    # --- Build the starting zone -------------------------------------------------
    zone: dict[tuple[str, str], RRset] = {}
    apex: str | None = None
    soa_record: Record | None = None
    start_records: list[Record] = []

    for index, raw in enumerate(start):
        record = normalize_record(raw, 0, index)
        start_records.append(record)
        if record.rtype == "SOA":
            if soa_record is not None:
                raise ReplayError(
                    "INITIAL_SOA_MULTIPLE",
                    "apex_must_have_one_soa",
                    0,
                    record=index,
                )
            soa_record = record
            apex = record.name
        _add(zone, record, 0, index)

    if soa_record is None or apex is None:
        raise ReplayError("INITIAL_SOA_MISSING", "start_must_include_soa")

    for index, record in enumerate(start_records):
        if not _name_in_zone(record.name, apex):
            raise ReplayError(
                "NAME_OUTSIDE_ZONE", "record_name_outside_zone", 0, record=index
            )

    current_serial: int = soa_record.rdata[2]

    # --- Apply changes sequentially, each atomically -----------------------------
    # (old SOA, new SOA, non-SOA deletes, non-SOA adds) per applied change,
    # captured only when a rollback plan was requested.
    applied: list[tuple[Record, Record, list[Record], list[Record]]] = []
    for change_index, raw_change in enumerate(changes, start=1):
        if not isinstance(raw_change, dict):
            raise ReplayError(
                "INVALID_CHANGE", "change_must_be_object", change_index
            )
        deletes = _records_list(raw_change.get("deletes"), change_index, "deletes")
        adds = _records_list(raw_change.get("adds"), change_index, "adds")
        if not deletes or not adds:
            raise ReplayError(
                "INVALID_CHANGE",
                "change_must_delete_and_add",
                change_index,
            )

        candidate = copy.deepcopy(zone)

        # First operation must be the *current* SOA.
        first = normalize_record(deletes[0], change_index, 0)
        if first.rtype != "SOA":
            raise ReplayError(
                "CHANGE_MUST_START_WITH_SOA",
                "first_delete_must_be_current_soa",
                change_index,
                record=0,
            )
        if first.name != apex:
            raise ReplayError(
                "SOA_NOT_AT_APEX", "soa_must_be_at_apex", change_index, record=0
            )
        if first.rdata[2] != current_serial:
            raise ReplayError(
                "CHANGE_MUST_START_WITH_SOA",
                "first_delete_must_be_current_soa",
                change_index,
                record=0,
            )
        if not _record_existing(candidate, first):
            # It names the current serial but is otherwise not the live RR
            # (TTL/timers differ), so it is still a delete that misses.
            raise ReplayError(
                "DELETE_NOT_FOUND",
                "delete_must_hit_existing_record",
                change_index,
                record=0,
            )
        _delete(candidate, first, change_index, 0)

        # Remaining deletes: ordinary RRs only, each must exist.
        deleted: list[Record] = []
        for position, raw_record in enumerate(deletes[1:], start=1):
            record = normalize_record(raw_record, change_index, position)
            if not _name_in_zone(record.name, apex):
                raise ReplayError(
                    "NAME_OUTSIDE_ZONE",
                    "record_name_outside_zone",
                    change_index,
                    record=position,
                )
            if record.rtype == "SOA":
                raise ReplayError(
                    "UNEXPECTED_SOA",
                    "only_one_soa_pair_per_change",
                    change_index,
                    record=position,
                )
            _delete(candidate, record, change_index, position)
            deleted.append(record)

        # Adds: the last operation is the new unique SOA.
        added: list[Record] = []
        for position, raw_record in enumerate(adds, start=1):
            record = normalize_record(raw_record, change_index, position)
            is_last = position == len(adds)
            if record.rtype != "SOA" and not _name_in_zone(record.name, apex):
                raise ReplayError(
                    "NAME_OUTSIDE_ZONE",
                    "record_name_outside_zone",
                    change_index,
                    record=position,
                )
            if is_last and record.rtype != "SOA":
                raise ReplayError(
                    "CHANGE_MUST_END_WITH_SOA",
                    "last_add_must_be_new_soa",
                    change_index,
                    record=position,
                )
            if record.rtype == "SOA":
                if not is_last:
                    raise ReplayError(
                        "UNEXPECTED_SOA",
                        "new_soa_must_be_last_add",
                        change_index,
                        record=position,
                    )
                if record.name != apex:
                    raise ReplayError(
                        "SOA_NOT_AT_APEX",
                        "soa_must_be_at_apex",
                        change_index,
                        record=position,
                    )
                if not serial_advances(current_serial, record.rdata[2]):
                    raise ReplayError(
                        "SERIAL_NOT_ADVANCED",
                        "serial_must_advance_per_rfc1982",
                        change_index,
                        record=position,
                    )
            _add(candidate, record, change_index, position)
            added.append(record)

        # The candidate must finish with exactly one SOA at the apex.
        apex_types = _types_at(candidate, apex)
        if "SOA" not in apex_types or len(candidate[(apex, "SOA")].rdatas) != 1:
            raise ReplayError(
                "SOA_NOT_UNIQUE", "apex_must_have_one_soa", change_index
            )

        zone = candidate
        current_serial = _soa_serial(zone, apex)
        if rollback_serials is not None:
            # The last add is guaranteed to be the new SOA at this point.
            applied.append((first, added[-1], deleted, added[:-1]))

    result = build_snapshot(zone, apex, current_serial, len(changes))
    if rollback_serials is not None:
        # Serials are checked against the forward final serial only after the
        # whole forward replay succeeded; any failure here still yields no
        # snapshot and no partial plan.
        _validate_rollback_serials(rollback_serials, current_serial)
        result["rollback_changes"] = build_rollback_plan(applied, rollback_serials)
    return result


def _soa_serial(zone: dict[tuple[str, str], RRset], apex: str) -> int:
    rdata = next(iter(zone[(apex, "SOA")].rdatas))
    return rdata[2]


# ---------------------------------------------------------------------------
# Rollback plan generation
# ---------------------------------------------------------------------------


def _validate_rollback_serials(
    rollback_serials: list[int], final_serial: int
) -> None:
    """Each rollback serial must strictly advance per RFC 1982: the first
    from the forward final serial, every next one from its predecessor."""

    previous = final_serial
    for step, serial in enumerate(rollback_serials, start=1):
        if not serial_advances(previous, serial):
            raise ReplayError(
                "ROLLBACK_SERIAL_NOT_ADVANCED",
                "rollback_serial_must_advance_per_rfc1982",
                rollback=step,
            )
        previous = serial


def _soa_with_serial(record: Record, serial: int) -> Record:
    """The same SOA RR — owner, TTL, mname/rname and timers — new serial."""

    rdata = (record.rdata[0], record.rdata[1], serial, *record.rdata[3:])
    return Record(name=record.name, rtype=record.rtype, ttl=record.ttl, rdata=rdata)


def build_rollback_plan(
    applied: list[tuple[Record, Record, list[Record], list[Record]]],
    rollback_serials: list[int],
) -> list[dict[str, Any]]:
    """Invert the applied forward changes, in reverse order.

    Step 1 undoes the last forward change. Every step opens by deleting the
    SOA that is live at that rollback moment — the forward final SOA for
    step 1, thereafter the previous step's closing SOA (historical
    parameters, previous rollback serial) — and closes by re-adding the
    historical SOA parameters with the serial prescribed for that step.
    Non-SOA records are inverted member-wise in reverse order, so feeding
    the plan back to :func:`replay` with the forward ``records`` as the
    starting zone restores each earlier zone version step by step.
    """

    plan: list[dict[str, Any]] = []
    total = len(applied)
    for step in range(1, total + 1):
        old_soa, new_soa, deleted, added = applied[total - step]
        live_serial = new_soa.rdata[2] if step == 1 else rollback_serials[step - 2]
        opening_soa = _soa_with_serial(new_soa, live_serial)
        closing_soa = _soa_with_serial(old_soa, rollback_serials[step - 1])
        plan.append(
            {
                "deletes": [_record_payload(opening_soa)]
                + [_record_payload(record) for record in reversed(added)],
                "adds": [_record_payload(record) for record in reversed(deleted)]
                + [_record_payload(closing_soa)],
            }
        )
    return plan


# ---------------------------------------------------------------------------
# Canonical output + digest
# ---------------------------------------------------------------------------


def _rdata_fields(rtype: str, rdata: tuple[Any, ...]) -> dict[str, Any]:
    if rtype == "SOA":
        return {
            "mname": rdata[0],
            "rname": rdata[1],
            "serial": rdata[2],
            "refresh": rdata[3],
            "retry": rdata[4],
            "expire": rdata[5],
            "minimum": rdata[6],
        }
    if rtype in ("A", "AAAA"):
        return {"address": rdata[0]}
    if rtype == "CNAME":
        return {"target": rdata[0]}
    return {"text": rdata[0]}


def _rdata_tokens(rtype: str, rdata: tuple[Any, ...]) -> list[str]:
    if rtype == "SOA":
        return [str(part) for part in rdata]
    return [str(rdata[0])]


def _record_payload(record: Record) -> dict[str, Any]:
    """Canonical request/response shape for one normalized record."""

    payload: dict[str, Any] = {
        "name": record.name,
        "type": record.rtype,
        "ttl": record.ttl,
    }
    payload.update(_rdata_fields(record.rtype, record.rdata))
    return payload


def canonical_records(
    zone: dict[tuple[str, str], RRset]
) -> list[dict[str, Any]]:
    keys = sorted(zone, key=lambda key: (key[0], RTYPE_ORDER[key[1]]))
    result: list[dict[str, Any]] = []
    for name, rtype in keys:
        rrset = zone[(name, rtype)]
        for rdata in sorted(rrset.rdatas, key=lambda rd: _rdata_tokens(rtype, rd)):
            record = {"name": name, "type": rtype, "ttl": rrset.ttl}
            record.update(_rdata_fields(rtype, rdata))
            result.append(record)
    return result


def snapshot_digest(zone: dict[tuple[str, str], RRset]) -> str:
    lines: list[str] = []
    for name, rtype in sorted(zone, key=lambda key: (key[0], RTYPE_ORDER[key[1]])):
        rrset = zone[(name, rtype)]
        for rdata in sorted(rrset.rdatas, key=lambda rd: _rdata_tokens(rtype, rd)):
            tokens = [name, rtype, str(rrset.ttl), *_rdata_tokens(rtype, rdata)]
            lines.append(" ".join(tokens))
    canonical = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_snapshot(
    zone: dict[tuple[str, str], RRset],
    apex: str,
    final_serial: int,
    changes_applied: int,
) -> dict[str, Any]:
    return {
        "apex": apex,
        "final_serial": final_serial,
        "changes_applied": changes_applied,
        "records": canonical_records(zone),
        "sha256": snapshot_digest(zone),
    }
