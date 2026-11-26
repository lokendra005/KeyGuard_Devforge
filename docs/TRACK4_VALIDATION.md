# Track 4 validation - 27 November 2026

[Raw committed evidence](../evidence/README.md) and [review resolutions](REVIEW_RESOLUTION.md) provide reproducible checks. Results apply to the source manifest in `evidence/source-sha256.json`; final archive checks accompany the release separately.

| Check | Observed outcome |
|---|---|
| Exact Node 24.11.1, offline Linux ARM64 | 57/57 tests, zero failures/skips |
| Exact Node 24.11.1, offline Linux AMD64 (emulated) | 57/57 tests, zero failures/skips |
| Independent ML-DSA verification vectors | 225/225 per architecture: 82 valid and 143 invalid cases |
| Unmodified organizer validator | 22 passing records, exit zero; host and fresh Linux process/container transport |
| Independent Python pqcrypto oracle | 16/16 random ML-KEM keypairs; exact decapsulation/HMAC, wrong key/content, replay and post-revocation checks |
| TLS | Real TLS 1.3 with trusted CA succeeds; untrusted CA and non-loopback plaintext fail |
| Actual TLS deployment | One authority + three independent cache containers on an internal network; allowed before revocation and denied afterward |
| Clean-checkout Docker | Root source-only build succeeds; image-contained tests and vectors pass |
| Five independent ARM64 nodes | L=3000 ms; p50=308 ms; p99/max=3004 ms; two partitions |
| Five independent AMD64 nodes | L=3000 ms; p50=312 ms; p99/max=2993 ms; two partitions |
| Synthetic held-out detector | TP=960, FP=0, FN=120, TN=10920; F1=0.9412 |
| Receipt-derived median alert delay | 83109.5 ms with injected receipt delay up to 120,000 ms |
| False-alerted events per 1,000 benign | 0 on the synthetic holdout |
| Signed API ingestion | 10,020 observations persisted and evaluated; no old 10k cutoff |
| Submission brief/video | Two-page PDF; 300-second 1280x720 narrated recorded-evidence video |

The suite uses real crypto, actual subprocess boundaries, real HTTP/CLI delivery, actual SIGKILL, separate node databases and injected transport delay/partitions. No crypto mock or skipped test is counted as a pass. The public validator's 22 records include setup and formatting checks, not 22 independent security proofs.

## Detector evaluation protocol

The default seed is 20261127; an independent renamed-seed run uses 987654321. Each has 4,000 earlier reference events and 12,000 disjoint held-out events. Parameters are fixed rather than fitted to labels. Events include renamed roles/actions/services, offsets within +/-300 seconds, receipt delays up to 120 seconds, delayed prerequisites, independent flow IDs, benign novelty and isolated denial decoys. The 120 false negatives are isolated stolen-credential accesses that remain ambiguous under these inputs; they are retained in the reported confusion matrix.

F1 is event-level. Median alert latency is calculated from supporting receipt timestamps and includes deliberate collection delay; it is not a live streaming or CPU benchmark. Timing uncertainty is retained. A frozen reference can be poisoned if its operator does not review it, and synthetic coverage does not predict real-world attack recall.

## Lease measurement and security scope

Five distinct OS processes use five different encrypted cache databases. Sync delay is injected at 50/150/300 ms; updates are withheld entirely for two nodes. A single observer polls after the central revocation acknowledgement. Polling/scheduling adds delay to the first observed denial (therefore a measured value can slightly exceed L even though the node's authorization check expired on time). Only five samples support each p99 value; this is not a production percentile estimate.

Deterministic tests check exact lease cutoff, stale-challenge replay, delayed response, wrong node/authority, tampered snapshot, forked chain, restart and monotonic rollback. The conditional authorization bound is L/(1-rho) under the clock-rate assumption in [the design](TRACK4_DESIGN.md). Nodes do not implement Byzantine consensus and a paused/stopped monotonic clock violates that assumption.

## Other operational boundaries

All routine data operations have explicit capacity limits. Security controls bypass the soft audit budget, but still need functioning durable storage. At-rest encryption protects database-only leakage; the whole state directory contains its master key. External anchors are required to detect known-prefix rollback. Native memory zeroization is not proven. Session resumption is intentionally unsupported. Hidden judge tests, independent cryptographic certification and production-scale accuracy/availability are not claimed.
