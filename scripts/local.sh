#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "${1:-start}" in
  stop) pg_ctl -D "$PWD/.local/pg" -m fast stop; exit;;
  start) ;;
  *) echo 'usage: scripts/local.sh [start|stop]' >&2; exit 1;;
esac
make build
if [ ! -d .local ]; then ./dist/kig init --dir .local; fi
if [ ! -d .local/pg ]; then initdb -D "$PWD/.local/pg" -A trust -U kiglocal --no-locale >/dev/null; fi
if ! pg_ctl -D "$PWD/.local/pg" status >/dev/null 2>&1; then
 pg_ctl -D "$PWD/.local/pg" -l "$PWD/.local/pg.log" -o "-k $PWD/.local -h '' -p 55438" -w start >/dev/null
fi
export DATABASE_URL="postgres://kiglocal@/postgres?host=$PWD/.local&port=55438&sslmode=disable"
./dist/kig migrate
exists=$(psql "$DATABASE_URL" -Atc 'SELECT count(*) FROM kig_authority')
if [ "$exists" = 0 ]; then ./dist/kig bootstrap --audit-key .local/audit.json --genesis .local/genesis.json; fi
exec ./dist/kig serve --min-protocol "${KIG_MIN_PROTOCOL:-2}" --listen 127.0.0.1:8443 --audit-key .local/audit.json --tls-cert .local/tls-cert.pem --tls-key .local/tls-key.pem
