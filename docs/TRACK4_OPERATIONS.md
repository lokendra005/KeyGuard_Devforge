# Track 4 operator runbook

## Initialize a separate authority

Use Node 24.11.1. `node track4/cli.cjs help` lists every command. Choose a new private directory; do not reuse the Go ledger's `.local` directory or database. An initialized authority rejects another setup.

Generate keys with `keygen --out PATH`; output is exclusive, mode 0600. Use separate administrator, user and at least two recovery-custodian keys. Keep private keys on their endpoints; setup contains public keys only. Public keys are SPKI DER in Base64.

Replace every placeholder in this setup schema with your data:

```json
{
  "owners": {"YOUR_ASSET": "YOUR_USER"},
  "contents": {"YOUR_ASSET": "YOUR_CONTENT"},
  "disabled": [],
  "key_material": "YOUR_SYNTHETIC_ORGANIZER_VALUE",
  "identities": [
    {"actor":"YOUR_OPERATOR","role":"admin","public_key":"BASE64_SPKI"},
    {"actor":"YOUR_USER","role":"user","public_key":"BASE64_SPKI"},
    {"actor":"YOUR_RECOVERY_A","role":"recovery","public_key":"BASE64_SPKI"},
    {"actor":"YOUR_RECOVERY_B","role":"recovery","public_key":"BASE64_SPKI"}
  ]
}
```

The organizer's minimal setup omits identities: it asserts actors through the trusted worker boundary. Network use requires enrolled signing keys. Runtime keys/salts use the CSPRNG; placeholders are documentation, not defaults.

```sh
node track4/cli.cjs init --state /private/path/state --input setup.json
node track4/cli.cjs serve --state /private/path/state --port 8444
node track4/cli.cjs dashboard --url http://127.0.0.1:8444 --actor YOUR_OPERATOR --key operator.json
```

Open the service root and paste the observer token. Tokens expire after ten minutes, stay in browser memory and lose access on key cutoff, epoch change or revocation. They authorize observation only. A separate file control submits locally prepared signed commands.

## Operations

Put an operation in a JSON file and run `request --url URL --actor ID --key KEY --body FILE`.

| Body | Effect |
|---|---|
| `{"op":"read","actor":"...","asset":"...","request_id":"unique ID"}` | Current owner gets exact content; allow/deny is durably correlated. |
| `{"op":"put","actor":"...","asset":"...","version":0,"body":"..."}` | Owner creates a file; updates require its exact current version. |
| `{"op":"revoke","actor":"target"}` | Admin disables target, retires keys and removes relay work. Other owners retain access. |
| `{"op":"role.set","actor":"target","role":"auditor"}` | Admin changes role and advances epoch; demoting the last enabled admin is refused. |
| `{"op":"file.transfer","asset":"...","recipient":"...","version":1}` | Current owner/admin transfers ownership at the exact version, atomically re-encrypting the file with its new owner binding. |
| `{"op":"audit","request_id":"..."}` | Request owner or auditor/admin gets the decision. |
| `{"op":"evidence"}` / `{"op":"status"}` | Auditor/admin exports signed history or metadata. |
| `{"op":"detector.ingest","events":[...],"approvals":{"changes":[...]},"config":{...}}` | Admin ingests observations; later batches may reuse stored context. Conflicting event IDs fail. |

`prepare` writes an envelope for later `submit`; outputs never overwrite. Commands are single-use. After a timeout inspect state before issuing a new command. File writes have version checks; enrollment, rotation and recovery have conflict guards. There is no generic exactly-once network delivery claim.

Optional setup policy can lower limits: 10,000 files/events, 1 MiB per file, 16 MiB encrypted file storage, 1,000 relay records, 60-second maximum rotation grace, 120-second request lifetime and 300-second mailbox lifetime. JSON input is capped at 16 MiB; identity strings at 4096 UTF-8 bytes; observer tokens at 1,000 entries. Capacity exhaustion is explicit, never silent evidence deletion. Plan archival/new-authority governance before filling the bounded log.

## Rotation and recovery

```sh
node track4/cli.cjs keygen --out new-key.json
node track4/cli.cjs rotate --url http://127.0.0.1:8444 --actor YOUR_USER \
  --key old-key.json --new-key new-key.json --grace-ms 0
```

The response gives cutoff and epoch. Zero grace cuts over atomically. Fresh old-key requests work only before a nonzero cutoff; earlier-epoch envelopes fail immediately. Save the replacement key before submitting. Administrative/recovery identities can rotate too.

For loss, revoke the target first, generate a replacement at the recovered endpoint, then prepare one shared proposal:

```sh
node track4/cli.cjs recovery-prepare --url http://127.0.0.1:8444 \
  --target YOUR_USER --new-key replacement.json --out recovery-body.json
```

Two distinct surviving custodians each submit that same body using their own `request --actor ... --key ...` before expiry. Competing completed recovery and changed approvers invalidate stale work. This is two full signatures enforcing policy, not threshold cryptography.

## Encrypted delivery

Exchange trusted public identity files out of band: `{"actor":"...","public_key":"..."}`. The relay cannot pick replacement trusted keys. Run the recipient first:

```sh
node track4/cli.cjs receive --url http://127.0.0.1:8444 --actor RECIPIENT \
  --key recipient.json --peer sender-public.json --out received.bin
node track4/cli.cjs send --url http://127.0.0.1:8444 --actor SENDER \
  --key sender.json --peer recipient-public.json --input message.bin
```

The recipient publishes a signed ephemeral offer and waits up to two minutes. Messages are at most 1 MiB, in 16 KiB ciphertext chunks. Only complete authenticated plaintext is delivered. Queue acceptance and recipient acknowledgement differ. Expired offers require a fresh receiver. A crash between output and acknowledgement requires operator reconciliation; exclusive output creation prevents overwriting existing data. The authority never gets message secrets or ephemeral private keys.

## Backups and evidence

Put a random password of at least 16 bytes in a private file, not an argument. Back up authority and endpoint keys separately:

```sh
node track4/cli.cjs backup --state /private/path/state --password-file password.txt \
  --out authority-backup.json --checkpoint checkpoint.json
node track4/cli.cjs key-backup --key user.json --password-file password.txt --out user-backup.json
node track4/cli.cjs key-restore --input user-backup.json --password-file password.txt --out restored-user.json
node track4/cli.cjs restore --input authority-backup.json --password-file password.txt \
  --state /private/path/NEW_STATE --anchor checkpoint.json
```

Keep the latest checkpoint and audit public key independently of backup/API administration. Restore only creates a new directory. Wrong passwords, corrupt envelopes/keys/file tags and snapshots older than the anchor fail. Logical snapshots are bounded at 128 MiB; excess size fails explicitly.

Export evidence through a signed command or dashboard. `verify --input evidence.json --trust audit-public.json --anchor checkpoint.json` checks it against `{"public_key":"PINNED_BASE64_SPKI"}`. A checksum alone is not an authenticity anchor.

## Detection and deployment

`detect` accepts CSV events and JSON approvals/baseline; see `track4/examples/README.md`. Production offsets/uncertainty must come from trusted clock measurements. Labels are used only by the evaluator; ingestion never reads them. No AI/ML component is used.

Use `serve --host ADDRESS --cert cert.pem --tls-key key.pem --origin https://HOST:PORT` for TLS; clients use `--ca` for a private CA. HTTP is loopback-only. Host and Origin headers are checked; non-loopback startup without TLS/origin fails.

For Compose, initialize state and set `KIG_TRACK4_STATE`, `KIG_TLS_CERT`, `KIG_TLS_KEY`, `KIG_PUBLIC_ORIGIN`, plus matching `KIG_UID`/`KIG_GID`. Run `docker compose -f compose.track4.yaml up --build`. The published address defaults to host loopback. Additional local API processes need distinct ports/node IDs and the same state directory. Use a local filesystem with SQLite WAL locking, not an arbitrary network share.

`serve --anchor checkpoint.json` verifies startup history against an independently retained prefix. Refresh that external anchor through your custody process; an old checkpoint cannot detect an unseen lost suffix. Detector inputs are bounded at 10,000 events, with a default capacity of 1,024 events in one unexpected-path window; dense sequences fail explicitly instead of silently truncating evidence.

Go ledger commands, storage and rollback anchors remain separate. Track 4 checkpoints are not Go witness checkpoints. Existing deployments and pending signed migrations are untouched.
