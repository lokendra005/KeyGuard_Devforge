#!/bin/sh
# No package installation, network fetch or live authority mutation.
set -eu
cd "$(dirname "$0")/.."
case "${1:-}" in
  --docker)
    arch="${KIG_REVIEW_ARCH:-$(docker info --format '{{.Architecture}}')}"
    case "$arch" in arm64|aarch64) arch=arm64;; amd64|x86_64) arch=amd64;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
    docker load -i "dist/track4-node-$arch.tar" >/dev/null
    docker run --rm --pull never --platform "linux/$arch" --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 512m --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,size=256m -v "$PWD:/app:ro" -w /app "keyguard-review-node:$arch" sh -ec 'node --test track4/test/core.test.cjs track4/test/messaging.test.cjs track4/test/detect.test.cjs track4/test/http.test.cjs; node track4/test/vectors.cjs'
    ;;
  '')
    node --test track4/test/core.test.cjs track4/test/messaging.test.cjs track4/test/detect.test.cjs track4/test/http.test.cjs
    node track4/test/vectors.cjs
    ;;
  *) echo 'Usage: track4-review.sh [--docker]' >&2; exit 1;;
esac
