#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export PATH="$PWD/.cache/toolchain/bin:$PATH"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
export GOCACHE="${GOCACHE:-$PWD/.cache/build}"
export GOFLAGS=-mod=vendor
mkdir -p .cache
if [ -n "${KIG_TEST_DATABASE_URL:-}" ]; then
  go test -race -count=1 ./...
  exit
fi
for cmd in initdb pg_ctl go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required: $cmd. Install PostgreSQL or set KIG_TEST_DATABASE_URL. No network download is attempted." >&2
    exit 1
  fi
done
work=$(mktemp -d "${TMPDIR:-/tmp}/kig-tests.XXXXXX")
cleanup() {
  pg_ctl -D "$work/pg" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
initdb -D "$work/pg" -A trust -U kigtest --no-locale >/dev/null
# Unix sockets only: no public interface, no port collision, no shared developer database.
pg_ctl -D "$work/pg" -l "$work/pg.log" -o "-F -k $work -h '' -p 55439" -w start >/dev/null
export KIG_TEST_DATABASE_URL="postgres://kigtest@/postgres?host=$work&port=55439&sslmode=disable"
go test -race -count=1 -v ./...
if [ "${KIG_BENCH:-0}" = 1 ]; then go test ./internal/guard -run '^$' -bench BenchmarkPostgresTransfer -benchtime=100x -benchmem; fi
