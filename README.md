# KeyGuard — DevForge Track 4 ("Trust, but verify")

KeyGuard keeps files and messages safe when an identity key is **lost, replaced or abused**. Every action is signed with post-quantum cryptography, revocation is enforced on every node (and survives crashes and restarts), the audit log is tamper-evident, and a rule- and graph-based detector flags suspicious role changes and lateral movement. No AI/ML, no hard-coded keys, no npm packages.

| Submission item | Link |
|---|---|
| Two-page brief (USP, architecture, threat model) | [KeyGuard-brief.pdf on Google Drive](https://drive.google.com/file/d/1EWmpJ30gfHw9Pq14L_ov4nTrxADp8hgs/view) · [copy in this repo](docs/KeyGuard-brief.pdf) |
| Demo video (about 3 minutes) | [KeyGuard-demo.mp4 on Google Drive](https://drive.google.com/file/d/1QczF-sgEoiOMdhpSwBTvpjXlNi2HEmlr/view) |
| Both files | [Google Drive folder](https://drive.google.com/drive/folders/1PSfjDx8Oe8Mvfz7y5mz6MsXEh54Xfo05?usp=sharing) |
| Organizer adapter | [`track4_service.cjs`](track4_service.cjs) at the repository root |

## 1. Run it on a clean machine

Needs Git, curl, tar and a SHA-256 tool (Linux AMD64/ARM64 or macOS). The only runtime is **Node 24.11.1**, whose built-in OpenSSL 3.5.4 provides ML-KEM, ML-DSA and SLH-DSA and whose built-in SQLite stores state. The installer downloads it, checks the [official hashes](https://nodejs.org/download/release/v24.11.1/SHASUMS256.txt) and keeps it inside the project folder.

```sh
git clone https://github.com/lokendra005/KeyGuard_Devforge.git
cd KeyGuard_Devforge
./scripts/install-node.sh
export PATH="$PWD/.cache/node/current/bin:$PATH"
./scripts/demo.sh
```

Expected result: `tests 104`, `pass 104`, `fail 0`, then the detector benchmarks, performance numbers and a map of the 12 Track 4 goals. After the install step no network is needed. Docker alternative: `./scripts/demo.sh --docker` (same suite in the pinned Node image, offline, read-only).

Organizer checks (Python 3.12 with `pqcrypto==0.4.0`):

```sh
python3.12 /path/to/Track-4-Toolkit/validate.py --entry "$PWD/track4_service.cjs"   # 22/22 PASS
python3.12 track4/test/interop.py                                                    # 16/16 ML-KEM interop
```

## 2. How the judging adapter works

`track4_service.cjs` reads one JSON request from stdin and writes one JSON object to stdout per process, as in the organizer contract (`setup`, `read`, `revoke`, `audit`, `protected_read`). State lives in `$TRACK4_STATE_DIR/keyguard-track4`, falling back to the OS temp directory. `setup` resets the scenario atomically. Every change is committed before it is acknowledged, so a revoke holds across processes and crashes. Any error on `read`, `protected_read` or `audit` still answers in the contract shape with `"decision": "deny"` and never returns content. `protected_read` encapsulates to the caller's raw ML-KEM-768 key and returns the HMAC-SHA-256 proof over `challenge + body`.

## 3. See it working (2 minutes)

```sh
mkdir -p .local
node track4/examples/init.cjs .local/example          # fresh keys + editable setup.json
node track4/cli.cjs init  --state .local/authority --input .local/example/setup.json
node track4/cli.cjs serve --state .local/authority --port 8444      # terminal 2
```

In terminal 1 (`U=http://127.0.0.1:8444`):

```sh
printf '%s\n' '{"op":"read","actor":"owner","asset":"document","request_id":"r1"}' > .local/r1.json
printf '%s\n' '{"op":"read","actor":"owner","asset":"document","request_id":"r2"}' > .local/r2.json
printf '%s\n' '{"op":"revoke","actor":"owner"}' > .local/revoke.json
printf '%s\n' '{"op":"status"}' > .local/status.json

node track4/cli.cjs request --url $U --actor owner    --key .local/example/owner.json    --body .local/r1.json      # allow
node track4/cli.cjs request --url $U --actor operator --key .local/example/operator.json --body .local/revoke.json  # effective_everywhere_at_ms
node track4/cli.cjs request --url $U --actor owner    --key .local/example/owner.json    --body .local/r2.json      # UNAUTHORIZED
node track4/cli.cjs request --url $U --actor operator --key .local/example/operator.json --body .local/status.json  # security_alerts, tree_head
```

Detector on the organizer practice set (5 of 5 findings, 0 false alerts, ATT&CK IDs on every alert):

```sh
P=track4/test/fixtures/practice
node track4/cli.cjs detect --events $P/events.csv --approvals $P/approvals.json \
  --config track4/examples/practice-policy.json --labels $P/labels.csv \
  --positive-labels unexpected_role_change,review_after_role_change,lateral_movement_candidate
```

A browser dashboard is also available: `node track4/cli.cjs dashboard --url $U --actor operator --key .local/example/operator.json`, then open `http://127.0.0.1:8444` and paste the returned token.

## 4. Architecture

- **Identity and commands.** Each request is signed with ML-DSA-65 and bound to the authority, the destination node (audience), the key epoch, a one-time nonce and an expiry. Duplicate JSON fields are rejected.
- **Authority.** The policy check, the effect and the signed audit event commit in one SQLite transaction (write-ahead log, `synchronous=FULL`, `BEGIN IMMEDIATE`).
- **Tamper-evident audit.** A signed SHA-384 hash chain plus an RFC 9162 Merkle tree; audit answers carry inclusion proofs; tree heads are signed with ML-DSA-65 and SLH-DSA-SHA2-128s; per-record canonical JSON blocks log injection (CWE-117).
- **Read nodes.** Each replica keeps its own encrypted database and a challenge-bound lease (max 5 s), so a partitioned node stops serving on its own. Every sync must be signed by the node's own key with an increasing counter. Every revoking change reports `effective_everywhere_at_ms`.
- **Messaging.** One-time hybrid X25519 + ML-KEM-768 receiver offers per message, HKDF-SHA384, AES-256-GCM with associated data; the relay only holds ciphertext.
- **Recovery.** Two custodians from independent enrollment chains must approve a new key.
- **Detection.** Rules (role change, approval scope, revocation) plus an actor-wide service graph with ordered and cross-identity pivots; MITRE ATT&CK technique IDs on every alert; clock-offset intervals and hybrid logical clocks for out-of-order events.
- **Self-detection.** A command with a valid signature that is still rejected (revoked or expired key, disabled actor, stale epoch, signed replay) becomes a signed `security.alert` naming identity, key, node and event, capped at 20 per identity per minute. Response: that identity's dashboard sessions and pending message offers are revoked.

Details and security arguments: [docs/TRACK4_DESIGN.md](docs/TRACK4_DESIGN.md).

## 5. Measured results

All numbers come from committed evidence in [`evidence/`](evidence/README.md) and can be regenerated with `scripts/collect-evidence.sh --docker`.

| What | Result |
|---|---|
| Tests | 104/104 on offline Linux ARM64 and AMD64; organizer validator 22/22; pqcrypto interop 16/16 |
| Revocation time (100 revocations × 5 replicas) | p50 487 ms, p99 1,117 ms, max 1,168 ms; each revoke reports its guaranteed time (≤ 3,016 ms) |
| Partitioned node | Fails closed at lease expiry (about 2.9 s with a 3 s lease) |
| Rotation grace window | Configurable 0–60 s, enforced exactly at the cutoff |
| Timing range | ±300 s source clock offset, 120 s late arrival |
| Detector F1 | 0.9000 and 0.9630 on two independently written synthetic holdouts; 1.0 on the organizer practice set |
| Median time to alert | 83.65 s and 98.30 s |
| False alerts per 1,000 benign events | 21.98 and 0.00 |
| Performance | Adapter read about 23 ms; about 790 signed reads/s; 100,000 events analysed in about 1.4 s |

## 6. Known limits

- No Double Ratchet/PQXDH and no session resumption: each message uses a fresh one-time hybrid offer, so there is no post-compromise healing inside a session.
- A replica may honour a pre-revocation lease for under about one second; every revoke reports exactly when it holds on all nodes.
- The detector misses hops more than 30 minutes apart and pivots from sources whose clock offset exceeds 5 minutes; without any baseline or policy, normal fan-out can raise false alerts.
- Attempts rejected before signature verification (forged, wrong node) are counted, not attributed to an identity.
- The authority and replica hosts are trusted. The master key sits beside its database, so encryption at rest covers a database-only leak, not theft of the whole state directory.
- Synthetic detector scores are not production accuracy.

## 7. Repository layout

| Path | Contents |
|---|---|
| `track4_service.cjs` | Organizer adapter (entry point) |
| `track4/` | Implementation: `service.cjs` (operations), `auth.cjs`, `store.cjs`, `merkle.cjs`, `replica.cjs`, `replication.cjs`, `messaging.cjs`, `detect.cjs`, `lateral.cjs`, `hlc.cjs`, `server.cjs`, `cli.cjs`, `web/` dashboard |
| `track4/test/` | 104 tests, benchmarks, practice-set fixtures |
| `scripts/` | `install-node.sh`, `demo.sh`, evidence and brief builders |
| `docs/` | Brief PDF, design, operations runbook, validation, detector notes |
| `evidence/` | Committed logs and measurements behind every number |
| `Dockerfile`, `compose*.yaml` | Container build and TLS deployment with replicas |

More: [operations runbook](docs/TRACK4_OPERATIONS.md) · [reviewer notes](docs/SUBMISSION.md) · [validation summary](docs/TRACK4_VALIDATION.md) · [detector notes](docs/DETECTOR_PRECISION.md)
