#!/usr/bin/env bash
# One-shot verification entry point for the Compose "verify" service.
# Runs the build/syntax check, the full regression suite, then the HTTP smoke
# test (32-bit serial wraparound plus the rollback-plan round trip) against
# the running API. Reports the overall conclusion via its exit code and then
# exits.
set -euo pipefail

echo "==> [1/3] Build check (byte-compile)"
python -m compileall -q app tests scripts

echo "==> [2/3] Regression test suite"
python -m pytest

echo "==> [3/3] HTTP smoke test (wraparound + rollback plan) against ${API_BASE_URL}"
python scripts/smoke.py

echo "==> VERIFY OK"
