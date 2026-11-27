# Track 4 validation - 27 November 2026

[Raw committed evidence](../evidence/README.md) and [review resolutions](REVIEW_RESOLUTION.md) provide reproducible checks. Results apply to the source manifest in `evidence/source-sha256.json`; final archive checks accompany the release separately.

| Check | Observed outcome |
|---|---|
| Exact Node 24.11.1, offline Linux ARM64 | 87/87 tests, zero failures/skips |
| Exact Node 24.11.1, offline Linux AMD64 (emulated) | 87/87 tests, zero failures/skips |
| Independent ML-DSA verification vectors | 225/225 per architecture: 82 valid and 143 invalid cases |
| Unmodified organizer validator | 22 passing records, exit zero; host and fresh Linux process/container transport |
| Independent Python pqcrypto oracle | 16/16 random ML-KEM keypairs; exact decapsulation/HMAC, wrong key/content, replay and post-revocation checks |
| TLS (retained review-v3 evidence) | Real TLS 1.3 with trusted CA succeeds; untrusted CA and non-loopback plaintext fail |
| Actual TLS deployment (retained review-v3 evidence) | One authority + three independent cache containers on an internal network; allowed before revocation and denied afterward |
| Clean-checkout Docker | Root source-only build succeeds; image-contained tests and vectors pass |
| Revocation, 100 revocations x 5 replicas | sync 1000 ms, L=3000 ms; 500 observations; p50=492 ms, p95=1074 ms, p99=1108 ms, max=1119 ms; reported bound <= 3018 ms (`evidence/revocation-100.json`, host run) |
| Five independent ARM64 nodes | L=3000 ms; median=340 ms; max of 5 samples=2981 ms; two partitions |
| Five independent AMD64 nodes | L=3000 ms; median=342 ms; max of 5 samples=2946 ms; two partitions |
| Original synthetic holdout | TP=1080, FP=240, FN=0, TN=10680; F1=0.9000; median alert delay 83651.5 ms; 21.98 false-alerted events / 1000 benign |
| Independently written topology holdout | TP=1300, FP=0, FN=100, TN=11800; F1=0.9630; median delay 98295.5 ms; 0 false-alerted events / 1000 benign |
| Concurrent clock regression stress | 20 additional successful AMD64 runs, three fresh workers each |
| Signed API ingestion | 10,020 observations persisted and evaluated; no old 10k cutoff |
| Submission brief/video | Updated two-page PDF; earlier review-v3 300-second walkthrough is explicitly historical |
| Precision regression | Exhaustive pivot oracle across 4,000 observations; no previously detected attack events lost across 20 old/new comparisons |

The suite uses real crypto, actual subprocess boundaries, real HTTP/CLI delivery, actual SIGKILL, separate node databases and injected transport delay/partitions. No crypto mock or skipped test is counted as a pass. The public validator's 22 records include setup and formatting checks, not 22 independent security proofs.

## Detector evaluation protocol

The original generator uses seed 20261127 (renamed-seed check 987654321), 4,000 reference events and 12,000 held-out events. The independent generator uses an LCG, mesh/hub graph, outcome synonyms and distinct scenarios, with 3,600 reference and 13,200 evaluation events (seed 314159). Both files, including scenarios and labels, are byte-for-byte unchanged from review-v3. Both inject clock offsets and receipt delays.

Review-v4 changes the decision structure, not thresholds: ordered two-hop witnesses and trusted actor-route familiarity. F1 improves from 0.7500 to 0.9000 on the original holdout and 0.8966 to 0.9630 on the independent topology holdout. False positives are 240 and 0 respectively; true positives remain 1080 and 1300, and misses remain 0 and 100. Ten seeds per generator preserve every previously detected attack event. The same scenario families are reused across seeds, so this is not independent real-world validation. See [the full precision argument and limits](DETECTOR_PRECISION.md) and `evidence/detector-precision-validation.json`.
F1 is event-level. Median alert latency is calculated from supporting receipt timestamps and includes deliberate collection delay; it is not a live streaming or CPU benchmark. Timing uncertainty is retained. A frozen reference can be poisoned if its operator does not review it, and synthetic coverage does not predict real-world attack recall.

## Lease measurement and security scope

Five distinct OS processes use five different encrypted cache databases. Sync delay is injected at 50/150/300 ms; updates are withheld entirely for two nodes. A single observer polls after the central revocation acknowledgement. Polling/scheduling adds delay to the first observed denial (therefore a measured value can slightly exceed L even though the node's authorization check expired on time). The reported maximum is the max of 5 samples, not a population percentile estimate.

Deterministic tests check exact lease cutoff, stale-challenge replay, delayed response, wrong node/authority, tampered snapshot, forked chain, restart and monotonic rollback. The conditional authorization bound is L/(1-rho) under the clock-rate assumption in [the design](TRACK4_DESIGN.md). Nodes do not implement Byzantine consensus and a paused/stopped monotonic clock violates that assumption.

## Other operational boundaries

All routine data operations have explicit capacity limits. Security controls bypass the soft audit budget, but still need functioning durable storage. At-rest encryption protects database-only leakage; the whole state directory contains its master key. External anchors are required to detect known-prefix rollback. Native memory zeroization is not proven. Session resumption is intentionally unsupported. Hidden judge tests, independent cryptographic certification and production-scale accuracy/availability are not claimed.
