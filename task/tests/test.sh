#!/bin/bash
set -euo pipefail

mkdir -p /logs/verifier /app/output

# Phase A seals expectations from the independent reference engine and removes it.
# Phase B grades agent outputs with no oracle import (R181).
export PYTHONPATH=/tests
export PYTHONSAFEPATH=1
set +e
python3 -B /tests/derive_expectations.py
phase_one=$?
set -e
rm -f /tests/reference_engine.py /tests/derive_wrong_models.py /tests/derive_expectations.py

set +e
python3 -P -m pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
phase_two=$?
set -e

if [[ "$phase_one" -eq 0 && "$phase_two" -eq 0 ]]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
exit 0
