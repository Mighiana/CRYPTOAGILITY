#!/usr/bin/env bash
# Run the full CryptoAgility Lab pipeline on the synthetic fictional organization.
# Requires `make setup` (pinned OpenSSL 3.5.9 in .tools/). Evidence goes to $RESULTS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
RESULTS="${RESULTS:-results}"
ITERATIONS="${ITERATIONS:-20}"
WARMUPS="${WARMUPS:-3}"
CLI="${CRYPTOAGILITY_CLI:-$ROOT/.venv/bin/cryptoagility}"
if [[ ! -x "$CLI" ]]; then
    echo "cryptoagility CLI not found at $CLI; run 'make setup' first" >&2
    exit 2
fi
"$CLI" --openssl-version
"$CLI" lab "$RESULTS" --iterations "$ITERATIONS" --warmups "$WARMUPS" ${LAB_ARGS:-}
echo
echo "Open $RESULTS/report.html in a browser (offline, no external resources)."
