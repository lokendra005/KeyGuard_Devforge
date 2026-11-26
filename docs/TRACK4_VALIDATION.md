# Track 4 implementation validation — 27 November 2026

The earlier compatibility audit described the Go-only submission. The current root adapter and `track4/` implementation address that interface and add the protected-file, key-lifecycle, messaging and detection workflows. This report states measured outcomes, not hidden-test scores or independent certification.

## Recorded results

Logs are in `dist/validation/` in the workspace and `validation/` in the reviewer archive.

| Check | Observed result | Evidence |
|---|---|---|
| Unmodified organizer validator, commit `8901dfb` | 22 check records pass, exit 0 | `track4-official-validator.log` |
| Same validator, a fresh offline read-only Linux container for every request | Pass, exit 0 | `track4-official-linux.log` |
| Host regression suite | 38 tests pass, 0 fail, 0 skip; Node 24.7.0, macOS ARM64 | `track4-host.log` |
| Exact Node 24.11.1 Linux ARM64 | 38 tests pass, 0 fail, 0 skip | `track4-offline-arm64.log` |
| Exact Node 24.11.1 Linux AMD64, emulated on ARM64 | 38 tests pass, 0 fail, 0 skip | `track4-offline-amd64.log` |
| Built deployment image, offline and read-only | 38 tests pass, 0 fail, 0 skip; runs copied application files without source mounts | `track4-deployment-image.log` |
| Independent ML-DSA verification corpus, new Node/OpenSSL path | 225/225 NIST/Wycheproof cases: 82 valid, 143 invalid; both Linux architectures | `track4-vectors.log` and architecture logs |
| Independent Python `pqcrypto==0.4.0` decapsulation and HMAC oracle | 16 generated KEM keys pass; host and actual Linux adapter | `track4-interop.log`, `track4-interop-linux.log` |
| TLS deployment check | Actual trusted-CA TLS request succeeds; untrusted certificate and non-loopback plaintext fail | `track4-tls.log` |
| Legacy preservation | All 14 existing key files match their recorded SHA-384 hashes; six Go binaries match the previous tested archive byte-for-byte | `track4-legacy-preservation.log` |
| Public practice detection | Event-level TP=5, FP=0, FN=0, TN=17; F1=1.0; median receipt-derived delay 200 ms | `track4-practice.log` |

The Linux suite runs unprivileged with a read-only root/source, `--network none`, dropped capabilities and temporary writable state. Socket tests use loopback inside that isolated container. All checks execute actual production modules; crypto is not stubbed. The public validator's 22 records include formatting/setup checks and are not 22 independent security proofs.

The host's older Node supports the application path, whose domain separation is in the signed message. The full FIPS context-vector test requires Node 24.8+ and was executed on the supported 24.11.1 runtime, not counted as a host pass. OpenSSL is 3.5.4 inside that Node image. The supplied primitive vector corpus and provenance are reused from `internal/guard/testdata`, including its upstream license.

## Goal-by-goal evidence

| Published goal | Implemented evidence | Scope |
|---|---|---|
| Key rotation | New-key possession, epoch advance, explicit grace/cutoff, old/new requests, restart checks | Identity signing keys; master/audit key rotation is not claimed. |
| Revocation across nodes | Three separate worker processes read one shared authority, then all deny after acknowledged revocation | Final run observed 36 ms ARM64 / 481 ms emulated AMD64 after acknowledgement, including process startup; not geographical replication latency. |
| Crash recovery | SIGKILL inside an uncommitted rotation, followed by restart and old-version/file/revocation checks | Relies on SQLite/local-filesystem durability semantics. |
| Backup integrity | Encrypted key/authority backups, corrupt ciphertext, wrong password, stale anchor, verified restored access | External anchor custody and surviving password are assumed. |
| Log integrity | Signed SHA-384 chain, altered actor, truncation, embedded newline/JSON-like text and audit correlation | Trusted authority reports, not proof against a malicious host. |
| Routine/suspicious activity | Approval, role, timing and scope checks; independently evaluated public labels | 22 development examples plus generated-name rule tests; no general accuracy claim. |
| Lateral movement | Connected unexpected service graph with actor/session/flow grouping and event explanations | Attempts are distinguished from successful compromise; isolated denials do not imply a path. |
| Clock differences | Offset correction, raw timestamps, uncertainty, late prerequisites and out-of-order arrival | Measurement helper and supplied telemetry; no automatic NTP daemon. |
| Replay/recipient binding | Signed peer offers, bound message headers, AEAD, consumed offers, modified header/ciphertext tests | Independently pinned peer keys; trusted local worker is a separate boundary. |
| Forward secrecy | One-use ephemeral receiver keys stay in memory and disappear from live endpoint state after completion | Conditional cryptographic argument; not proof of physical memory erasure. |
| Loss/reordering | Omitted/shuffled/duplicate chunks, bounded retries, expiry failure, real CLI file delivery/acknowledgement | Application-level fault injection, not a physical WAN loss benchmark; no exactly-once external delivery across crashes. |
| Session resumption | Intentionally unsupported | Receiver restart requires a fresh signed offer; no reusable session secret is persisted. |

## Algorithm and implementation findings fixed during development

- Bound HKDF context through a SHA-384 transcript hash, retaining all authenticated fields while respecting the native HKDF API limit.
- Encode SQLite-bound strings losslessly; independently tested opaque identities/resources/request IDs include Unicode, empty strings and embedded NULs.
- Require canonical public-key DER. Native parsing alone can accept trailing bytes; the pinned negative vectors include overlong keys.
- Recheck current policy on a retried read correlation ID. Audit lookup returns the latest result while immutable events retain previous decisions; no cached allow survives revocation.
- Bind relay offers to the exact intended sender as well as recipient, and reject conflicting chunks or multiple messages consuming one offer.
- Make persistence/audit failures roll back key changes and content mutations; record rejects without assigning an unverified claimed identity to an authenticated actor.
- Preserve missing-key and unknown-storage-version fences rather than regenerating authority state.

## Performance sample

`track4-bench-linux.log` records 40 operations per type in Node 24.11.1 Linux ARM64 on this host. Signed read median was **1.64 ms**, p95 **3.31 ms**; protected-read median **1.59 ms**, p95 **2.40 ms**. Peak reported RSS was **57,428 KiB**. The measurement includes local command signing/verification, SQLite commit, audit signature and applicable KEM/HMAC, but excludes HTTP and process startup. It is a small local sample, not a throughput or production SLA claim.

## Reproduction and remaining boundaries

Use [SUBMISSION.md](SUBMISSION.md) for native, container, official-checker and independent-oracle commands. The archive includes exact Node runtime images for both architectures and the retained ledger's offline dependencies. Final extracted-artifact validation is recorded separately alongside the archive so its checksum is not changed by writing its own verification log.

The dashboard was opened against a separate generated authority and verified to load current resources, keys, detector explanations, corrected timelines and signed audit metadata. TLS and CLI-to-CLI delivery have executable tests. The prior live ledger was not migrated or replaced.

Unpublished judge tests, independent cryptographic audit, physical-memory erasure, Byzantine/distributed consensus, arbitrary network filesystems and production-scale detection accuracy remain unverified or outside scope. The qualifying public repository, final two-page PDF and accessible five-minute fallback video are still submission obligations; no URLs or eligibility claims have been fabricated.
