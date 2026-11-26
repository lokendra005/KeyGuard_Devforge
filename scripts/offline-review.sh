#!/bin/sh
# Complete review without a Go SDK or any network downloads.
set -eu
cd "$(dirname "$0")/.."
[ "$#" -le 1 ] || { echo 'Usage: offline-review.sh [--docker|--unit-only]' >&2; exit 1; }
case "${1:-}" in
 --docker)
  arch="${KIG_REVIEW_ARCH:-$(docker info --format '{{.Architecture}}')}"
  case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
  docker load -i "dist/postgres-image-$arch.tar" >/dev/null
  image="keyguard-review-postgres:$arch"
  name="kig-review-$$"
  cleanup(){ docker rm -fv "$name-db" >/dev/null 2>&1 || true; docker network rm "$name" >/dev/null 2>&1 || true; }
  trap cleanup EXIT INT TERM
  docker network create --internal "$name" >/dev/null
  docker run -d --platform "linux/$arch" --pull never --name "$name-db" --network "$name" --network-alias db --memory 512m -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_USER=review -e POSTGRES_DB=review "$image" >/dev/null
  attempt=0
  until docker exec "$name-db" pg_isready -U review -d review >/dev/null 2>&1; do
   attempt=$((attempt+1)); [ "$attempt" -lt 60 ] || { echo 'Review database startup failed' >&2; exit 1; }; sleep 1
  done
  docker run --rm --platform "linux/$arch" --pull never --network "$name" --user postgres --read-only --tmpfs /tmp:rw,mode=1777,size=256m --memory 1g --pids-limit 256 \
   -e KIG_TEST_DATABASE_URL='postgres://review@db:5432/review?sslmode=disable' \
   -v "$PWD/dist/guard-tests-linux-$arch:/guard-tests:ro" -v "$PWD/dist/spec-tests-linux-$arch:/spec-tests:ro" \
   --entrypoint sh "$image" -ec '/spec-tests -test.v; /guard-tests -test.v'
  # A separate container has no network interfaces except loopback; the smoke
  # workflow starts its own socket-only DB and actual TLS server inside it.
  docker run --rm --platform "linux/$arch" --pull never --network none --user postgres --read-only --tmpfs /tmp:rw,mode=1777,size=256m --memory 1g --pids-limit 256 \
   -e KIG_BIN=/kig -v "$PWD/dist/kig-linux-$arch:/kig:ro" -v "$PWD/scripts/smoke.sh:/smoke.sh:ro" \
   --entrypoint sh "$image" /smoke.sh
  exit
  ;;
 --unit-only|'') ;;
 *) echo 'Usage: offline-review.sh [--docker|--unit-only]' >&2; exit 1;;
esac
[ "$(uname -s)" = Linux ] || { echo 'Use --docker on non-Linux hosts.' >&2; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
if [ "${1:-}" != --unit-only ]; then
 : "${KIG_TEST_DATABASE_URL:?Set an isolated PostgreSQL DSN, use --docker, or explicitly pass --unit-only}"
fi
./dist/spec-tests-linux-"$arch" -test.v
./dist/guard-tests-linux-"$arch" -test.v
