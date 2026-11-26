#!/bin/sh
# Run under independent administration, with observer + witness keys unavailable to API host.
set -eu
: "${KIG_URL:?set server HTTPS origin}"
: "${KIG_CA:?set TLS CA path}"
: "${KIG_OBSERVER_KEY:?set observer signing key path}"
: "${KIG_AUDIT_TRUST:?set pinned audit public key path}"
: "${KIG_WITNESS_KEY:?set witness signing key path}"
: "${KIG_WITNESS_STATE:?set retained checkpoint path}"
KIG_BIN=${KIG_BIN:-./dist/kig}
KIG_AUDIENCE=${KIG_AUDIENCE:-keyguard}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
# An error stops the loop; restarting retains the last accepted checkpoint.
while :; do
  KIG_TOKEN=$("$KIG_BIN" session --url "$KIG_URL" --ca "$KIG_CA" --audience "$KIG_AUDIENCE" --key "$KIG_OBSERVER_KEY")
  export KIG_TOKEN
  i=0
  while [ "$i" -lt 40 ]; do
    "$KIG_BIN" export --url "$KIG_URL" --ca "$KIG_CA" --audience "$KIG_AUDIENCE" --out "$work/bundle.json"
    "$KIG_BIN" witness --bundle "$work/bundle.json" --audience "$KIG_AUDIENCE" --trust "$KIG_AUDIT_TRUST" --witness-key "$KIG_WITNESS_KEY" --state "$KIG_WITNESS_STATE" >/dev/null
    rm "$work/bundle.json"
    i=$((i+1))
    sleep 30
  done
done
