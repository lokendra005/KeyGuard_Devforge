# KeyGuard_Devforge

Post-quantum protected files, recoverable identities and encrypted delivery for DevForge Track 4. The judge adapter, CLI, API and dashboard share the authority core. Independent read nodes maintain signed policy chains and separate encrypted caches, and fail closed when their short leases expire.

**No API key, hosted service, model or npm installation is required.** Runtime decisions use ownership, live identity/key state, signed commands and cryptographic verification. Example names and baseline data are configuration, never expected-answer branches.

- [Two-page brief](docs/KeyGuard-brief.pdf) · [Five-minute fallback video](https://github.com/lokendra005/KeyGuard_Devforge/releases/download/review-v2/keyguard-demo.mp4)
- [Architecture, algorithms and conditional security arguments](docs/TRACK4_DESIGN.md)
- [Operator runbook](docs/TRACK4_OPERATIONS.md) · [Reviewer instructions](docs/SUBMISSION.md)
- [Committed test evidence](evidence/README.md) · [Security review resolution](docs/REVIEW_RESOLUTION.md)

## Dependencies and clean-machine setup

Runtime: **Node 24.11.1**, including its built-in OpenSSL 3.5.4 crypto and SQLite. Supported review platforms: Linux AMD64/ARM64. macOS works for local development. Initial setup needs Git, HTTPS/curl, tar and a SHA-256 utility; tests subsequently need no network. Docker is optional for the packaged runtime. The independent organizer oracle additionally uses Python 3.12 and `pqcrypto==0.4.0`; neither is a production dependency.

```sh
git clone https://github.com/lokendra005/KeyGuard_Devforge.git
cd KeyGuard_Devforge
./scripts/install-node.sh
export PATH="$PWD/.cache/node/current/bin:$PATH"
./scripts/demo.sh
```

The installer verifies pinned hashes from the [official Node 24.11.1 release](https://nodejs.org/download/release/v24.11.1/SHASUMS256.txt). It installs inside the ignored project cache, without modifying system Node. `demo.sh` executes all regression tests, independent signature vectors, the synthetic detector evaluation, performance sampling and an explicit map of all 12 goals. Session resumption is reported as unsupported, not counted as a pass.

## Start a working authority and dashboard

```sh
mkdir -p .local
node track4/examples/init.cjs .local/example
node track4/cli.cjs init --state .local/authority --input .local/example/setup.json
node track4/cli.cjs serve --state .local/authority --port 8444
```

The example generator writes fresh keys and an editable **setup.json** with owners, contents and public identities. In a second terminal:

```sh
node track4/cli.cjs dashboard --url http://127.0.0.1:8444 \
  --actor operator --key .local/example/operator.json
```

Open `http://127.0.0.1:8444` and paste the returned observer token. The dashboard shows real resources, identity state, detector evidence and audit checkpoints. To make a signed read:

```sh
printf '%s\n' '{"op":"read","actor":"owner","asset":"document","request_id":"first-read"}' > .local/read.json
node track4/cli.cjs request --url http://127.0.0.1:8444 \
  --actor owner --key .local/example/owner.json --body .local/read.json
```

Example IDs/content are editable. Private keys stay outside Git and outside the browser. Re-running the generator refuses to overwrite keys; production initialization refuses to replace existing state. The trusted judge adapter's `setup` instead resets its scenario transactionally. Non-loopback serving requires TLS and an explicit origin.

## Algorithms and measured limits

| Property | Implementation / measured result |
|---|---|
| Protected read | ML-KEM-768 plus exact organizer HMAC-SHA-256 challenge/content proof |
| Identity commands | ML-DSA-65, canonical JSON, epoch + nonce + expiry |
| Rotation grace | Configurable 0-60 seconds; partial transfers continue only while both peer keys remain valid |
| Independent-node revocation | Lease default 5 seconds; conditional authorization bound `L/(1-rho)` for monotonic clock drift bound `rho`; five-node ARM64 sample L=3000 ms: p50 308 ms, p99/max 3004 ms (includes polling) |
| Audit | Signed SHA-384 chain; external rollback checkpoint; first correlation decision retained; suffix verification for status |
| Detector | Frozen-reference frequency baseline, role-state/approval/revocation rules and time-decayed connected paths; no ML |
| Timing envelope | Default +/-300-second measured offset; 120-second lateness; raw timestamps and uncertainty retained |
| Synthetic holdout | 4,000 reference + 12,000 held-out events; F1 **0.9412**, TP 960 / FP 0 / FN 120 / TN 10,920 |
| Median alert delay | **83,109.5 ms**, receipt-derived with injected delays up to 120 s; not CPU latency |
| False-alerted events / 1,000 benign | **0** on this synthetic holdout; not a production accuracy claim |

The held-out generator renames services, actions and roles and includes benign novelty, skew, late arrivals and known misses. Training/evaluation windows cannot overlap. An isolated stolen-credential access can remain indistinguishable from a legitimate novel path; the detector does not hide that false-negative tradeoff.

## Containers and offline review

`docker build -t keyguard-track4 .` works from a clean clone; it does not require prebuilt files in `dist/`. The exact base digest is pinned. `compose.yaml` supplies the authoritative TLS API; `compose.replicas.yaml` adds separately mounted read nodes. See the runbook for certificates, origins, credentials and state ownership.

The [review-v2 release](https://github.com/lokendra005/KeyGuard_Devforge/releases/tag/review-v2) includes a checksummed reviewer bundle with both runtime images. Extract it, run `sha256sum -c SHA256SUMS`, then `./scripts/demo.sh --docker`. Tests run unprivileged with networking disabled, a read-only root/source and temporary writable state. Committed logs remain available without downloading that bundle. `scripts/collect-evidence.sh` regenerates them.

## Security boundaries

The trusted worker is local, not an unsigned network API. The authority and replica hosts are trusted; the relay alone cannot decrypt client messages. Master keys live beside their databases, so encryption at rest protects a **database-only leak**, not theft of the entire state directory. Lease guarantees assume a progressing monotonic clock, including host suspension; queued network bytes can arrive after authorization expires. Lost receiver state requires a new ephemeral offer. Unpublished judge tests and independent cryptographic certification are not claimed.

The optional Go/PostgreSQL implementation is contained under [legacy/](legacy/README.md), outside the default build and reviewer bundle. Its provenance and repository history remain visible; no eligibility claim is inferred from directory layout.
