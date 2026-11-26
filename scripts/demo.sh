#!/bin/sh
# Generate evidence from executable assertions, never canned verdicts or operator state.
set -eu
cd "$(dirname "$0")/.."
case "${1:-}" in
 --docker)
  arch="${KIG_REVIEW_ARCH:-$(docker info --format '{{.Architecture}}')}"
  case "$arch" in arm64|aarch64) arch=arm64;; amd64|x86_64) arch=amd64;; *) exit 2;; esac
  if [ -f "dist/track4-node-$arch.tar" ]; then docker load -i "dist/track4-node-$arch.tar" >/dev/null; fi
  exec docker run --rm --pull never --platform "linux/$arch" --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 768m --pids-limit 128 --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,size=384m -v "$PWD:/app:ro" -w /app "keyguard-review-node:$arch" sh scripts/demo.sh
  ;;
 '') ;;
 *) echo 'Usage: scripts/demo.sh [--docker]' >&2; exit 2;;
esac
node -e 'if(process.version!=="v24.11.1")throw Error("Use Node 24.11.1 or scripts/demo.sh --docker")'
printf '\nKEYGUARD: reproducible Track 4 demonstration\n'
node track4/test/walkthrough.cjs
node --test track4/test/*.test.cjs
node track4/test/vectors.cjs
printf '\nHELD-OUT DETECTOR (reference and evaluation windows are disjoint)\n'
node track4/test/detector-benchmark.cjs
printf '\nCRYPTO + TRANSACTION PERFORMANCE\n'
node track4/test/bench.cjs
printf '\n12-GOAL EVIDENCE MAP\n'
node track4/test/goal-map.cjs
