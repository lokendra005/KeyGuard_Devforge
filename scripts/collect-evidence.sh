#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p evidence
if [ "${1:-}" = --docker ]; then
 KIG_REVIEW_ARCH=arm64 ./scripts/demo.sh --docker > evidence/demo-arm64.log 2>&1
 KIG_REVIEW_ARCH=amd64 ./scripts/demo.sh --docker > evidence/demo-amd64.log 2>&1
else
 ./scripts/demo.sh > evidence/demo-native.log 2>&1
fi
node track4/test/detector-benchmark.cjs > evidence/detector-holdout.json
node track4/test/detector-benchmark.cjs 987654321 > evidence/detector-renamed-holdout.json
if [ -n "${TOOLKIT_DIR:-}" ]; then
 "${PYTHON:-python3.12}" "$TOOLKIT_DIR/validate.py" --entry "$PWD/track4_service.cjs" > evidence/official-validator.log 2>&1
 "${PYTHON:-python3.12}" track4/test/interop.py > evidence/pqcrypto-interop.log 2>&1
fi
node scripts/verify-evidence.cjs --record
printf 'Evidence regenerated. TOOLKIT_DIR and PYTHON enable the external organizer/oracle checks.\n'
