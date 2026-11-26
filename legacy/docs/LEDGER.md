# Key Identity Guard

A runnable post-quantum authorization service with a local signing CLI, operator dashboard, PostgreSQL authority, two-person key recovery and independently verifiable audit history. It implements a synthetic integer ledger as the protected workflow: the actual balance change and the final authorization check commit in the **same transaction**.

**Historical ledger runbook.** These Go interfaces are separate from the implemented Track 4 service; see [the current architecture](TRACK4_DESIGN.md) and [operator commands](TRACK4_OPERATIONS.md).

No external APIs, model downloads, CDN assets, hosted authentication or internet connection are needed at runtime. Go dependencies are vendored. Start with the offline test command before deploying.

For the algorithm and maths, start with [the cryptographic derivation and assurance report](CRYPTOGRAPHY.md). It separates lattice-signature security from authorization invariants. The [implemented v2 protocol and migration runbook](PROTOCOL_V2.md) specify the SHA-384 upgrade while preserving existing keys and v1 evidence. `make crypto` runs independent NIST/Wycheproof vectors, signing edge cases and both finite models without PostgreSQL.

Fresh installations use v2. Existing deployments require the explicit signed migration before starting with the default minimum protocol 2; installing the binary never silently upgrades a database.

## Quick start

Requirements: Go **1.26.11 or newer**, PostgreSQL 16+ tools (`initdb`, `pg_ctl`, `psql`), a C toolchain for race tests, and a non-root account. The Go version is a minimum, not a recommendation to stay on an unpatched runtime. OpenSSL 3.5+ enables an optional independent ML-DSA interoperability test.

```sh
make build
make test                 # isolated PostgreSQL, race detector, adversarial tests, finite model
./scripts/smoke.sh        # real TLS server + CLI + recovery + witness + process restart
./scripts/local.sh       # persistent local service at https://127.0.0.1:8443
```

The local script initializes keys only if `.local` does not exist. It uses an isolated Unix-socket PostgreSQL instance, never your existing databases. Ctrl-C stops the API; `./scripts/local.sh stop` stops its database. The generated localhost certificate is self-signed: use the explicit CA below. For a browser, trust only this development certificate or provide a properly issued certificate. Do not disable TLS verification in automation.

In another terminal:

```sh
./dist/kig session --url https://127.0.0.1:8443 --ca .local/tls-cert.pem --key .local/admin.json
```

Paste the short-lived token into the dashboard. It stays in browser memory, not localStorage. The dashboard inspects real identities, resource balances, recovery requests and audit events. It can submit requests signed by the CLI; private signing keys never enter the browser.

### Exercise the protected workflow

Every mutating `act` requires a new `--out` path. The exact signed request is fsynced **before** transmission. If the outcome is uncertain, use `submit` on that same file; do not invent a new operation ID.

```sh
./dist/kig act --url https://127.0.0.1:8443 --ca .local/tls-cert.pem \
  --key .local/admin.json --action resource.create --resource treasury \
  --body '{"balance":1000}' --out .local/create-treasury.json
./dist/kig act --url https://127.0.0.1:8443 --ca .local/tls-cert.pem \
  --key .local/admin.json --action resource.create --resource reserve \
  --body '{"balance":0}' --out .local/create-reserve.json
./dist/kig act --url https://127.0.0.1:8443 --ca .local/tls-cert.pem \
  --key .local/writer.json --action resource.transfer --resource treasury --version 1 \
  --body '{"to":"reserve","amount":25,"to_version":1}' --out .local/transfer.json
./dist/kig submit --url https://127.0.0.1:8443 --ca .local/tls-cert.pem --request .local/transfer.json
```

Use `prepare` instead of `act` to sign without submitting, then load that JSON in the dashboard. Signed files expire after 60 seconds by default. Identical already-committed retries can return the original non-sensitive receipt after expiry, but only while the signer retains current authority. `resource.transfer` is a sandbox workflow, not a banking integration.

## Container deployment

The Compose deployment has a restricted runtime database role, separate migration credentials, a non-root/read-only application container, TLS, an internal database network and no exposed database port. Images are pinned by digest. The image build copies a precompiled static executable into scratch and needs no base-image download.

```sh
make build
./dist/kig init --dir .local  # only on a fresh deployment; never overwrites keys
export KIG_UID=$(id -u) KIG_GID=$(id -g)
make release
docker compose build api
docker compose --profile setup up -d bootstrap
# Confirm bootstrap exited successfully; run only once per new database.
docker compose logs bootstrap
docker compose up -d api
```

Do not run the local service and Compose on the same port simultaneously. Compose reads only the server's audit/TLS keys and database credentials; it does not mount user or recovery private keys into the API. Move recovery and witness keys to separate operator custody after initialization. See [operations](OPERATIONS.md) for recovery, independent witnessing, backups and air-gapped deployment.

## What is implemented

- FIPS 204 **ML-DSA-65**, domain-separated pure signatures; OpenSSL interoperability tests in both directions.
- Embedded independent NIST known-answer and Wycheproof adversarial vectors; expanded-key checks and verification before returning a signature.
- Versioned SHA-384 body/key/history commitments and an audited v1-to-v2 cutover with downgrade guards.
- Exact action/body/audience/resource/version/expiry binding with an unambiguous binary signing representation.
- Registered keys, proof of possession for enrollment/recovery, strict bounded JSON, persisted one-use challenges and durable idempotency.
- Live role/key/subject checks, permanent key revocation, quarantine, two-distinct-identity recovery and session invalidation.
- Integer-only transfers with nonnegative balances, conservation and optimistic versions on both resources.
- PostgreSQL row-lock serialization across processes; effect, consumed challenge, idempotency result and audit event commit together.
- RFC 6962 Merkle checkpoints, signed action replay, an independent witness CLI and durable anti-rollback state.
- An embedded responsive dashboard, TLS server, graceful shutdown, bounded HTTP concurrency and fail-closed authority access.
- Offline source builds, static Linux binaries, deployment setup, model exploration, mutation/concurrency/failure tests and runbooks.

## Repository map

| Path | Purpose |
|---|---|
| `cmd/kig` | One executable: server, signing client, verification, witness and setup |
| `internal/guard/protocol.go` | Byte specification, strict decoding and ML-DSA |
| `internal/guard/state.go` | Single shared policy/transition function |
| `internal/guard/store.go` | PostgreSQL transaction boundary and persistence |
| `internal/guard/audit.go` | Merkle checkpoints and signed-history replay |
| `internal/guard/http.go`, `client.go`, `web/` | HTTP, CLI transport and dashboard |
| `spec/` | Bounded revocation and competing-recovery models with unsafe negative controls |
| `internal/guard/crypto_vectors_test.go`, `testdata/` | Pinned independent cryptographic vectors embedded into offline tests |
| `scripts/` | Offline tests, TLS smoke test, local run, witness and release |
| `docs/` | Protocol, security argument, operations, validation and next-track plan |

The app is a modular monolith, not a microservice framework. State is a bounded JSONB aggregate under one authority-row lock, with a separate append-only event table. This makes the invariant auditable but serializes a deployment's protected actions. It is not a high-volume multi-tenant ledger. Read the capacity and trust limits before extending it.

For the self-contained submission archive, start with [the reviewer runbook](SUBMISSION.md) and [the final security review](SECURITY_REVIEW.md).

## Reviewer entrypoints

```sh
make test                 # full tests: requires local PostgreSQL, or KIG_TEST_DATABASE_URL
make unit                 # unit/model tests; DB tests explicitly skip without that variable
make crypto               # independent crypto vectors + both finite models; no DB required
make vet
make fuzz
make bench
make release              # Linux amd64/arm64 binaries + vendored source archive
./dist/kig verify --bundle evidence.json --trust audit-public.json --audience keyguard
./dist/kig crypto-verify --key signer-public.json --message message.bin \
  --signature signature.bin --context KIG/action/v2
```

These documented CLI/HTTP interfaces are application interfaces, not the now-published organizer adapter. Algorithm-only tests can exercise `crypto-sign`/`crypto-verify` without PostgreSQL. See the [current Track 4 design](TRACK4_DESIGN.md), [validation results](VALIDATION.md), [protocol](PROTOCOL.md) for field/byte definitions and [security](SECURITY.md) for the precise proof assumptions.

**Assurance boundary:** this is tested software, not an independently audited or universally formally verified product. The finite model and conditional invariant argument do not prove the Go compiler, cryptographic library, database, operating system, or all possible deployment errors correct. Never silently replace the local transactional effect with a remote API call and retain the same guarantee.
