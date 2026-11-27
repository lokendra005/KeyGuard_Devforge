# KeyGuard_Devforge

Post-quantum protected files, recoverable identities and encrypted delivery for DevForge Track 4. The judge adapter, CLI, API and dashboard share the authority core. Independent read nodes maintain signed policy chains and separate encrypted caches, and fail closed when their short leases expire.

**No API key, hosted service, model or npm installation is required.** Runtime decisions use ownership, live identity/key state, signed commands and cryptographic verification. Example names and baseline data are configuration, never expected-answer branches.

- [Two-page brief](docs/KeyGuard-brief.pdf) · [Earlier walkthrough (review-v3; previous detector results)](https://drive.google.com/file/d/12ctCr6DAvSzDgRySdrr2QayL8FVswcMR/view) · [Download earlier walkthrough](https://github.com/lokendra005/KeyGuard_Devforge/releases/download/review-v3/keyguard-demo.mp4)
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
| Identity commands | ML-DSA-65, canonical JSON v2, destination audience + epoch + nonce + expiry |
| Rotation grace | Configurable 0-60 seconds; partial transfers continue only while both peer keys remain valid |
| Independent-node revocation | Lease default 5 seconds; conditional authorization bound `L/(1-rho)` for monotonic clock drift bound `rho`; 100 revocations x 5 replicas (sync 1 s, L=3000 ms): stolen-key requests rejected after p50 492 ms, p99 1,108 ms, max 1,119 ms; revoke reports a bound of at most 3,018 ms ([evidence](evidence/revocation-100.json)); partition run: partitioned nodes deny by 2,981 ms |
| Audit | Signed SHA-384 chain; external rollback checkpoint; first correlation decision retained; suffix verification for status |
| Detector | Frozen reference, configurable outcome synonyms (unknown outcomes counted; on role changes they fail closed), role/approval/revocation rules, actor-wide undirected components and cross-identity two-hop pivots; malformed or conflicting records are quarantined, not fatal; 30-minute window / 10-minute half-life; no ML |
| Timing envelope | Default +/-300-second measured offset; 120-second lateness; raw timestamps and uncertainty retained |

Two generators are implemented separately and use disjoint reference/evaluation windows. The first holdout's scenarios and labels are unchanged; the second uses a different random source, mesh/hub topology, vocabulary and attack mix. Both use the current defaults, without fitting thresholds to labels.

| Synthetic evaluation | Original holdout | Independent topology holdout |
|---|---:|---:|
| Reference / evaluated events | 4,000 / 12,000 | 3,600 / 13,200 |
| TP / FP / FN / TN | 1,080 / 240 / 0 / 10,680 | 1,300 / 0 / 100 / 11,800 |
| F1 | **0.9000** | **0.9630** |
| Precision / recall | 0.8182 / 1.0000 | 1.0000 / 0.9286 |
| Median receipt-derived alert delay | 83,651.5 ms | 98,295.5 ms |
| False-alerted events per 1,000 benign | 21.98 | 0 |

The precision update separates ordered two-hop pivots from two spokes and distinguishes familiar routes from role violations, without changing thresholds or either generator. Compared with review-v3, false positives fall from 720 to 240 on the original holdout and from 200 to 0 on the topology holdout. All previously detected attack events remain detected across ten seeds per generator; the topology holdout still has 100 isolated-attack misses. Unknown benign three-edge fan-out remains ambiguous and alertable. These are synthetic results, not production accuracy. [Algorithm, correctness argument, regression oracle and limitations](docs/DETECTOR_PRECISION.md).

The review-v5 robustness update leaves both holdout results unchanged and adds: an exact regression test on the organizer practice set (all 5 labelled findings alerted, 0 false alerts; operator approve/revoke events are labelled `approval_administration`), cross-identity pivots for credential hopping, per-record quarantine (`rejected`, `rejected_approvals`) that is never silent (a conflicting copy raises `conflicting_event_record` on the analysed copy; other quarantined records raise one `input_integrity` alert per reason naming identities and services), subject-scoped revocation with reinstatement, and incident-preserving component rebuilds. One identity emitting 100,000 unusual edges is analysed in about 1.3 s with a few hundred incidents (previously out of memory). Known blind spots: hops further apart than the 30-minute window, and two-hop pivots whose source clock offset exceeds `max_offset_ms`.

## Containers and offline review

`docker build -t keyguard-track4 .` works from a clean clone; it does not require prebuilt files in `dist/`. The exact base digest is pinned. `compose.yaml` supplies the authoritative TLS API; `compose.replicas.yaml` adds separately mounted read nodes. See the runbook for certificates, origins, credentials and state ownership.

The [review-v4 release](https://github.com/lokendra005/KeyGuard_Devforge/releases/tag/review-v4) includes a checksummed reviewer bundle with both runtime images. Extract it, run `sha256sum -c SHA256SUMS`, then `./scripts/demo.sh --docker`. Tests run unprivileged with networking disabled, a read-only root/source and temporary writable state. Committed logs remain available without downloading that bundle. `scripts/collect-evidence.sh` regenerates them.

## Security boundaries

The trusted worker is local, not an unsigned network API; any worker read, protected read or audit error answers in the contract shape with `decision: "deny"` (audits of unknown IDs add `recorded: false`). Recovery needs two custodians from independent enrollment lineages, and a signed command cannot remove the last admin. A replica sync exports file plaintext only to a caller holding both the replicator credential and the bound node's private key: the node signs each request with a strictly increasing counter, so a stolen replicator credential or a captured request is refused (`REPLICA_PROOF_REQUIRED`, `REPLAY`). Admin credentials can acquire every file through audited ownership changes. Every replica sync records its node, exported count, checkpoint, lease and uploaded-log acknowledgement; admin credentials cannot call sync. Every revoking change (revoke, rotate, role change, ownership transfer, completed recovery) reports `effective_everywhere_at_ms`, the latest expiry of any lease granted before it (and, for rotation, the old key's cutoff); the CLI waits until then before reporting the change as effective on every node. The HTTP body pool is bounded per peer (4 uploads, 16 MiB buffered), globally (512 uploads, 256 MiB) and in time (5 s), and GETs never use body slots. The authority and replica hosts are trusted; the relay alone cannot decrypt client messages. Master keys live beside their databases, so encryption at rest protects a **database-only leak**, not theft of the entire state directory. Lease guarantees assume a progressing monotonic clock, including host suspension; queued network bytes can arrive after authorization expires. Lost receiver state requires a new ephemeral offer. Unpublished judge tests and independent cryptographic certification are not claimed.

The optional Go/PostgreSQL implementation is contained under [legacy/](legacy/README.md), outside the default build and reviewer bundle. Its provenance and repository history remain visible.
