# Operation, deployment and offline review

Protocol v2 is now the default. For existing v1 state, follow [the signed SHA-384 migration procedure](PROTOCOL_V2.md) before using the default v2-only server. It preserves key files and historical evidence; never delete/rebootstrap a database to upgrade its suite.

## Initial trust

`kig init --dir PATH` creates a fresh mode-0700 directory and refuses existing paths. It produces separate user, recovery, observer, audit and witness keys, public-only trust files, a genesis manifest, local TLS material and random database credentials. This is an explicit synthetic deployment initializer, not silent key regeneration on server startup.

Before exposing a deployment, move the two recovery keys to distinct operators and the witness key/checkpoint to another administrative domain. The service never needs those private keys. Pin and distribute `audit-public.json` and `witness-public.json` through a trusted channel independent of received bundles. New trust roots require an explicit re-bootstrap and migration plan.

Local setup is convenient and binds only loopback. Container setup binds host loopback by default as well. Public exposure requires an appropriate issued TLS certificate and intentional network configuration; do not blindly publish a synthetic test installation. The included certificate covers localhost/127.0.0.1/::1 only.

## Database and schema

Migration is explicit: `kig migrate` uses owner credentials. Bootstrap is explicit and refuses a second genesis: `kig bootstrap --audit-key ... --genesis ...`. Normal service startup neither migrates nor regenerates keys. It verifies the replayed history against authority state before listening.

Compose initialization creates `kig_app` with only the runtime table privileges it needs. The API uses its separate DSN. Owner credentials are mounted only into migrate/bootstrap jobs. Runtime cannot mutate/delete existing audit rows or create schema objects. Both share the private Docker network; PostgreSQL is not published on the host.

On Linux, set `KIG_UID` and `KIG_GID` to the dedicated host user's numeric IDs owning the secret files. Do not make private keys world-readable to fix permissions. Bind-mounted Compose secrets inherit host storage permissions and are not encrypted by Compose. Migration/setup containers run as root inside their restricted containers solely to access operator-owned setup files; the long-running API is non-root.

## Common commands

Set server and trust options explicitly on each CLI command:

```
--url https://127.0.0.1:8443 --ca .local/tls-cert.pem --audience keyguard
```

Prefer `DATABASE_URL_FILE` for server credentials and `KIG_TOKEN` for read tokens. Do not put private keys, DB passwords or tokens into source control, screenshots, logs or distributable bundles. The repository excludes `.local` and `.cache`; release scripts whitelist source paths.

### Revocation and quarantine

```
kig act ... --key admin.json --action key.revoke --resource KEY_FINGERPRINT --out revoke-request.json
kig act ... --key admin.json --action subject.quarantine --resource writer --out quarantine-request.json
```

Revoking one key is permanent. Quarantine disables the subject. Both invalidate its read sessions and prepared requests at their next final authority check. Receipts from earlier commits remain historical facts. Retrying an operation after revocation does not restore access.

### Recovery

```
kig keygen --subject writer --out new-writer.json
kig recovery-body --key new-writer.json --role writer \
  --recovery-id incident-2026-01 --expires UNIX_SECONDS --out recovery-body.json
kig act ... --key recovery1.json --action recovery.approve --resource writer \
  --body @recovery-body.json --out approval-one.json
kig act ... --key recovery2.json --action recovery.approve --resource writer \
  --body @recovery-body.json --out approval-two.json
```

Use one identical proposal body for both approvals, including expiry within one hour. Transfer the new public enrollment proposal to approvers, not the new private key. Confirm new-key possession and target identity out of band before approving. The second approval revokes old keys; it does not make their IDs valid again. If a recovery authority itself is compromised, stop affected workflows and conduct an audited root replacement; there is no ordinary-key escape hatch.

### Evidence and independent witnessing

```
export KIG_TOKEN=$(kig session ... --key observer.json)
kig export ... --out evidence.json
kig verify --bundle evidence.json --trust audit-public.json --audience keyguard
kig witness --bundle evidence.json --trust audit-public.json --audience keyguard \
  --witness-key witness.json --state witness-state.json
kig verify --bundle evidence.json --trust audit-public.json --audience keyguard \
  --anchor witness-state.json --witness-trust witness-public.json
```

`witness` acquires an exclusive lock file, verifies signatures/replay and prefix extension, then fsyncs and atomically replaces retained state before acknowledging. If it crashes and leaves `.lock`, confirm no witness process remains and investigate before manually removing that lock. Do not delete accepted state to resolve a fork error.

`scripts/witness.sh` automates this on a separately controlled host. Configure the documented environment variables at its top. It renews an observer session periodically, verifies every fetched bundle and stops on any error. Run it under a process supervisor with alerting. Its observer key has read authority only; its witness private key must not be available to the API host.

The release uses full-history verification, not a remote universal transparency service. A checkpoint proves extension relative to retained history. It does not prove that the executor truthfully recorded every real-world action.

## Backup and restore

1. Take a consistent PostgreSQL backup (`pg_dump`) of the complete authority and event tables. Do not back up only balances.
2. Keep the latest independently accepted witness checkpoint outside that backup and outside API administration.
3. Retain immutable binary/image identifiers, public trust roots, schema version and encrypted private-key backups separately.
4. Restore into an isolated database. Do not overwrite a running deployment during investigation.
5. Start with `--anchor witness-state.json --witness-trust witness-public.json`. Startup rejects shorter/forked history and state/history mismatch. Normal authority transactions also enforce that configured anchor.
6. If restored state predates the independent anchor, remain quarantined; recover the missing history or conduct an explicit newly trusted deployment. Do not remove `--anchor` to make it start.

For Compose, use `docker compose -f compose.yaml -f compose.witnessed.yaml up -d api` after supplying independently retained `.local/witness-state.json` and public witness trust. The configured anchor is loaded at startup: refresh it from independent custody before each restore/restart. It does not magically discover an unseen latest checkpoint. Recent unobserved commits and external freshness are separate durability concerns.

Rollback application versions only when the old code understands the existing schema/protocol. Never reset epochs, drop operations/nonces, rewrite event sequence, or regenerate audit keys to work around a compatibility error. The server's explicit event-capacity limit is not permission to prune security state.

## Air-gapped reviewer delivery

### Source path

`make release` produces Linux amd64/arm64 static executables and a source archive containing pinned dependencies under `vendor/`. Go commands set `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local`: no network fallback is allowed. The reviewer must already have the documented Go toolchain and PostgreSQL. `make test` creates its own temporary Unix-socket database, never installs software, and fails with a clear prerequisite message if PostgreSQL is absent. An existing isolated test DSN can be supplied as `KIG_TEST_DATABASE_URL`.

`make unit` explicitly skips DB tests without a DSN; it is not evidence of database coverage. `make test` is the required complete test command. `make smoke` also requires curl and runs an actual TLS process on loopback port 18443.

### Container path

Before disconnecting, build once and save the application and exact database image:

```
docker save keyguard:local postgres:16-alpine > keyguard-images.tar
```

On an offline machine of the **same architecture**:

```
docker load < keyguard-images.tar
# Generate fresh local keys, set KIG_UID/GID, then:
docker compose --profile setup up --no-build --pull never -d bootstrap
docker compose up --no-build --pull never -d api
```

Do not distribute your `.local` secrets. Building the scratch image offline requires only the precompiled architecture-specific executable from `make release`; no Go builder image is needed. A tar saved from an ARM64 Docker host is not automatically an AMD64 deployment image: provide the architecture-specific binary, build for that platform, or package separately. Release checksums cover binaries/source; Docker image digests cover image identities.

## Failure handling and capacity

- `AUTHORITY_UNAVAILABLE`: refuse effects; restore primary access, not cached permissions.
- `OUTCOME_UNKNOWN` or transport timeout: preserve request and retry exactly; never mint a replacement ID automatically.
- `CLOCK_REGRESSION`: investigate primary clock; do not rewrite audit timestamps.
- `RESTORE_QUARANTINE` / invalid anchor: stop and reconcile history.
- `CAPACITY`: do not delete nonces/history; migrate to an intentionally designed bounded archival/storage release.
- `STALE_RESOURCE`: fetch latest authorized state and obtain approval for a new request; do not silently alter a signed body.
- Witness outage: protected commits can continue, but no new independent witness guarantee exists. Monitor the separately retained checkpoint, not a UI guess.

The API's hard ceilings, single authority lock and snapshot storage deliberately trade scale for a short inspectable correctness argument. Size, lock contention and export latency must be benchmarked for the intended workload before raising those ceilings.

### Review without a Go SDK

`make release` also produces `guard-tests-linux-{amd64,arm64}` and `spec-tests-linux-{amd64,arm64}`. Supply them beside the application binary in `dist/`, then run:

```
KIG_TEST_DATABASE_URL='postgres://...isolated-test-database...' ./scripts/offline-review.sh
```

These test executables need no Go SDK or dependency download. They use the supplied PostgreSQL instance and create/drop only their own randomly named test schemas. `--unit-only` explicitly permits skipping database cases. OpenSSL interoperability is an optional extra when OpenSSL 3.5+ is installed; other cryptographic tests always execute. The precompiled tests do not include the race detector; the source `make test` run does.
