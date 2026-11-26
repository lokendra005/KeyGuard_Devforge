#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
BIN="${KIG_BIN:-$PWD/dist/kig}"
[ -x "$BIN" ] || make build
work=$(mktemp -d "${TMPDIR:-/tmp}/kig-smoke.XXXXXX")
server_pid=''
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  pg_ctl -D "$work/pg" -m fast stop >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
initdb -D "$work/pg" -A trust -U kigtest --no-locale >/dev/null
pg_ctl -D "$work/pg" -l "$work/pg.log" -o "-k $work -h '' -p 55439" -w start >/dev/null
export DATABASE_URL="postgres://kigtest@/postgres?host=$work&port=55439&sslmode=disable"
"$BIN" init --dir "$work/keys" --protocol 1
cp -R "$work/keys" "$work/original-keys"
"$BIN" migrate
"$BIN" bootstrap --audit-key "$work/keys/audit.json" --genesis "$work/keys/genesis.json"
"$BIN" serve --min-protocol 1 --listen 127.0.0.1:18443 --audit-key "$work/keys/audit.json" --tls-cert "$work/keys/tls-cert.pem" --tls-key "$work/keys/tls-key.pem" >"$work/server.log" 2>&1 &
server_pid=$!
protocol=1
client(){ "$BIN" "$@" --protocol "$protocol" --url https://127.0.0.1:18443 --ca "$work/keys/tls-cert.pem"; }
i=0
until client ready >/dev/null 2>&1; do
  i=$((i+1)); if [ "$i" -gt 50 ]; then cat "$work/server.log" >&2; exit 1; fi
  sleep 0.1
done
client act --key "$work/keys/admin.json" --action resource.create --resource treasury --body '{"balance":1000}' --out "$work/create1.json" >/dev/null
client act --key "$work/keys/admin.json" --action resource.create --resource reserve --body '{"balance":0}' --out "$work/create2.json" >/dev/null
client act --key "$work/keys/writer.json" --action resource.transfer --resource treasury --version 1 --body '{"to":"reserve","amount":25,"to_version":1}' --out "$work/transfer.json" >"$work/first-result.json"
client submit --request "$work/transfer.json" >"$work/retry-result.json"
cmp "$work/first-result.json" "$work/retry-result.json"
client prepare --key "$work/keys/writer.json" --action resource.transfer --resource treasury --version 2 --body '{"to":"reserve","amount":1,"to_version":2}' --out "$work/pre-cutover.json"
KIG_TOKEN=$(client session --key "$work/keys/observer.json"); export KIG_TOKEN
client export --out "$work/v1-evidence.json"
"$BIN" witness --min-protocol 1 --bundle "$work/v1-evidence.json" --trust "$work/keys/audit-public.json" --witness-key "$work/keys/witness.json" --state "$work/witness.json" >/dev/null
"$BIN" upgrade-body --bundle "$work/v1-evidence.json" --trust "$work/keys/audit-public.json" --anchor "$work/witness.json" --witness-trust "$work/keys/witness-public.json" --out "$work/upgrade.json"
protocol=2
client act --key "$work/keys/admin.json" --action protocol.upgrade --resource protocol --body "@$work/upgrade.json" --out "$work/upgrade-request.json" >"$work/upgrade-result.json"
client submit --request "$work/upgrade-request.json" >"$work/upgrade-retry.json"
cmp "$work/upgrade-result.json" "$work/upgrade-retry.json"
if client submit --request "$work/pre-cutover.json" >"$work/unexpected" 2>"$work/denial"; then echo 'v1 write survived cutover' >&2; exit 1; fi
grep -q PROTOCOL_VERSION "$work/denial"
if client state >"$work/unexpected" 2>"$work/denial"; then echo 'old session survived cutover' >&2; exit 1; fi
grep -q UNAUTHORIZED "$work/denial"
"$BIN" verify --min-protocol 1 --bundle "$work/v1-evidence.json" --trust "$work/keys/audit-public.json" >/dev/null
if "$BIN" verify --bundle "$work/v1-evidence.json" --trust "$work/keys/audit-public.json" >"$work/unexpected" 2>"$work/denial"; then echo 'v2 default accepted old-only evidence' >&2; exit 1; fi
for original in "$work/original-keys/"*; do cmp "$original" "$work/keys/$(basename "$original")"; done
client prepare --key "$work/keys/writer.json" --action resource.transfer --resource treasury --version 2 --body '{"to":"reserve","amount":10,"to_version":2}' --out "$work/stale.json"
client act --key "$work/keys/admin.json" --action subject.quarantine --resource writer --out "$work/quarantine.json" >/dev/null
if client submit --request "$work/stale.json" >"$work/unexpected" 2>"$work/denial"; then echo 'revoked write succeeded' >&2; exit 1; fi
grep -q REVOKED "$work/denial"
"$BIN" keygen --subject writer --out "$work/new-writer.json"
"$BIN" recovery-body --key "$work/new-writer.json" --role writer --recovery-id incident-1 --expires "$(( $(date +%s) + 600 ))" --out "$work/recovery.json"
client act --key "$work/keys/recovery1.json" --action recovery.approve --resource writer --body "@$work/recovery.json" --out "$work/approve1.json" >/dev/null
client act --key "$work/keys/recovery2.json" --action recovery.approve --resource writer --body "@$work/recovery.json" --out "$work/approve2.json" >/dev/null
client act --key "$work/new-writer.json" --action resource.transfer --resource treasury --version 2 --body '{"to":"reserve","amount":10,"to_version":2}' --out "$work/recovered-transfer.json" >/dev/null
KIG_TOKEN=$(client session --key "$work/keys/observer.json"); export KIG_TOKEN
client state >/dev/null
client export --out "$work/evidence.json"
"$BIN" verify --bundle "$work/evidence.json" --trust "$work/keys/audit-public.json" >"$work/verified.json"
"$BIN" witness --bundle "$work/evidence.json" --trust "$work/keys/audit-public.json" --witness-key "$work/keys/witness.json" --state "$work/witness.json" >/dev/null
"$BIN" verify --bundle "$work/evidence.json" --trust "$work/keys/audit-public.json" --anchor "$work/witness.json" --witness-trust "$work/keys/witness-public.json" >/dev/null
kill "$server_pid"; wait "$server_pid"; server_pid=''
"$BIN" serve --listen 127.0.0.1:18443 --audit-key "$work/keys/audit.json" --anchor "$work/witness.json" --witness-trust "$work/keys/witness-public.json" --tls-cert "$work/keys/tls-cert.pem" --tls-key "$work/keys/tls-key.pem" >"$work/restart.log" 2>&1 &
server_pid=$!
i=0
until client state >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 50 ]; then cat "$work/restart.log" >&2; exit 1; fi; sleep 0.1; done
printf '%s\n' 'PASS: v1-to-v2 SHA-384 cutover, unchanged key files, downgrade denial, migration retry, TLS, transfer, revocation, recovery, offline replay, witness continuity, v2-pinned restart.'
