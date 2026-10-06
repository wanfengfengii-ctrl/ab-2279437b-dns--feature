# Authoritative DNS — Offline IXFR Replay

Apply an incremental zone change log (IXFR) **offline, before promotion to
production**. The whole ordered set of changes is validated and applied to a
private copy first; any invalid change rejects the entire replay with a stable,
change-located error code and **no partial snapshot is ever returned**.

## Request

`POST /api/dns/ixfr/replay`

```json
{
  "start": [ <RR>, ... ],
  "changes": [
    { "deletes": [ <RR>, ... ], "adds": [ <RR>, ... ] }
  ],
  "rollback_serials": [ <u32>, ... ]   // optional
}
```

* `start`: starting zone records — `SOA`, `A`, `AAAA`, `CNAME`, `TXT` — and must
  contain exactly one SOA.
* `changes`: **1–64** ordered changes; total records across the request
  (start + every delete/add) must not exceed **5000**.
* `rollback_serials` *(optional)*: exactly one 32-bit serial per forward
  change, **in rollback order**. The first must strictly advance from the
  forward final serial and each subsequent one from the previous rollback
  serial (same RFC 1982 rules). When present, the response gains a
  publishable `rollback_changes` plan (see below). When omitted, the
  request/response/summary/error semantics are exactly as before.

Record shape:

| Type  | Fields |
|-------|--------|
| SOA   | `name, ttl, mname, rname, serial, refresh, retry, expire, minimum` |
| A     | `name, ttl, address` (IPv4) |
| AAAA  | `name, ttl, address` (IPv6, compressed form accepted) |
| CNAME | `name, ttl, target` |
| TXT   | `name, ttl, text` |

## Enforced rules

1. Every change **starts by deleting the current SOA** (matching its serial)
   and **ends with a single unique new SOA**.
2. The new serial must **strictly advance per RFC 1982 32-bit serial
   arithmetic**, including wraparound (`2^32-2 → 2^32-1 → 0 → 1`).
3. Every delete must hit an **existing, identical RR** (name/type/TTL/rdata).
4. Every add must be new — no duplicate of an existing RR or of another add in
   the same change.
5. Records of one RRset must share a **single TTL** (change a TTL by deleting
   the old RRset members and re-adding them in one change).
6. A **CNAME cannot coexist with any other data** at the same owner name, and
   there cannot be two distinct CNAME targets at one name.
7. The apex always holds **exactly one SOA**; SOAs never move off the apex.
8. Zone and record names are **case-insensitively normalized** (canonical
   lowercase; a single trailing dot is accepted as absolute form).

## Response

`200 OK`

```json
{
  "apex": "example.com",
  "final_serial": 1,
  "changes_applied": 3,
  "records": [ { "name": "...", "type": "...", "ttl": 300, ... } ],
  "sha256": "<sha-256 of the canonical, stably ordered snapshot>",
  "rollback_changes": [
    { "deletes": [ <RR>, ... ], "adds": [ <RR>, ... ] }
  ]
}
```

`rollback_changes` is present only when `rollback_serials` was supplied. It
inverts the forward changes in reverse order: step 1 undoes the last forward
change, opening with the SOA live at that rollback moment and closing with
the historical SOA parameters carrying the prescribed rollback serial.
Resubmitting it against the forward `records` restores each earlier zone
version step by step:

```json
{ "start": <forward records>, "changes": <rollback_changes> }
```

replays cleanly and ends with the original zone content — every canonical
record and the SOA parameters — except the SOA serial, which finishes at the
last rollback serial.

`422 Unprocessable Entity` for an unpublishable log:

```json
{
  "error": {
    "code": "DELETE_NOT_FOUND",
    "rule": "delete_must_hit_existing_record",
    "change": 1,
    "record": 1,
    "message": "..."
  }
}
```

`change` is 1-based (`0` denotes the starting zone); `record` locates the
offending entry within that change's delete/add sequence (0-based). Rollback
validation failures additionally carry `rollback`, the 1-based rollback step
at fault, and never return the forward snapshot or a partial plan.

### Stable error codes

| Code | Meaning |
|------|---------|
| `REQUEST_MALFORMED` / `REQUEST_LIMIT` | Bad envelope (incl. malformed `rollback_serials`), or >5000 records / >64 changes |
| `INVALID_RECORD` | Malformed field, bad address/name, unsupported type |
| `INITIAL_SOA_MISSING` / `INITIAL_SOA_MULTIPLE` | Starting zone SOA invariants |
| `CHANGE_MUST_START_WITH_SOA` | First delete is not the current SOA |
| `CHANGE_MUST_END_WITH_SOA` | Last add is not a new SOA |
| `UNEXPECTED_SOA` | Extra/misplaced SOA inside a change |
| `SOA_NOT_AT_APEX` / `SOA_NOT_UNIQUE` | Apex SOA invariants |
| `SERIAL_NOT_ADVANCED` | RFC 1982 serial not strictly forward |
| `ROLLBACK_SERIALS_MISMATCH` | `rollback_serials` count differs from `changes` count |
| `ROLLBACK_SERIAL_NOT_ADVANCED` | Rollback serial not strictly forward per RFC 1982 |
| `DELETE_NOT_FOUND` | Delete misses an existing RR (incl. TTL mismatch) |
| `RECORD_DUPLICATE` | Add duplicates existing/same-change RR |
| `TTL_MISMATCH` | RRset members carry different TTLs |
| `CNAME_CONFLICT` | CNAME coexists with other data |
| `NAME_OUTSIDE_ZONE` | Record owner is outside the zone apex |

## Running with Docker

```bash
# Host port is configurable (default 8080):
HOST_PORT=9090 docker compose up --build -d api
curl -s http://localhost:9090/healthz
```

### One-shot verification

The `verify` service runs the build check, the full regression suite, and an
HTTP smoke test against the live API — including a serial-wraparound replay
and a rollback-plan round trip — then exits and reports the verdict via its
exit code:

```bash
docker compose up --build verify
docker inspect --format '{{.State.ExitCode}}' $(docker compose ps -q verify)
# 0 = all checks passed
```

## Local development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest
uvicorn app.api:app --reload
```
