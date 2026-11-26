# Track 4 validation - 27 November 2026

[Raw committed evidence](../evidence/README.md) and [review resolutions](REVIEW_RESOLUTION.md) provide reproducible checks. Results apply to the source manifest in `evidence/source-sha256.json`; final archive checks accompany the release separately.

| Check | Observed outcome |
|---|---|
| Exact Node 24.11.1, offline Linux ARM64 | 74/74 tests, zero failures/skips |
| Exact Node 24.11.1, offline Linux AMD64 (emulated) | 74/74 tests, zero failures/skips |
| Independent ML-DSA verification vectors | 225/225 per architecture: 82 valid and 143 invalid cases |
| Unmodified organizer validator | 22 passing records, exit zero; host and fresh Linux process/container transport |
| Independent Python pqcrypto oracle | 16/16 random ML-KEM keypairs; exact decapsulation/HMAC, wrong key/content, replay and post-revocation checks |
| TLS | Real TLS 1.3 with trusted CA succeeds; untrusted CA and non-loopback plaintext fail |
| Actual TLS deployment | One authority + three independent cache containers on an internal network; allowed before revocation and denied afterward |
| Clean-checkout Docker | Root source-only build succeeds; image-contained tests and vectors pass |
| Five independent ARM64 nodes | L=3000 ms; median=337 ms; max of 5 samples=3000 ms; two partitions |
| Five independent AMD64 nodes | L=3000 ms; median=327 ms; max of 5 samples=2954 ms; two partitions |
| Original synthetic holdout | TP=1080, FP=720, FN=0, TN=10200; F1=0.7500; median alert delay 82019 ms; 65.93 false-alerted events / 1000 benign |
| Independently written topology holdout | TP=1300, FP=200, FN=100, TN=11600; F1=0.8966; median delay 98295.5 ms; 16.95 false-alerted events / 1000 benign |
| Concurrent clock regression stress | 20 additional successful AMD64 runs, three fresh workers each |
| Signed API ingestion | 10,020 observations persisted and evaluated; no old 10k cutoff |
| Submission brief/video | Two-page PDF; 300-second 1280x720 narrated recorded-evidence video |

The suite uses real crypto, actual subprocess boundaries, real HTTP/CLI delivery, actual SIGKILL, separate node databases and injected transport delay/partitions. No crypto mock or skipped test is counted as a pass. The public validator's 22 records include setup and formatting checks, not 22 independent security proofs.

## Detector evaluation protocol

The original generator uses seed 20261127 (renamed-seed check 987654321), 4,000 reference events and 12,000 held-out events. Scenarios/labels remain unchanged. Actor-wide fan-out and two-successful-hop sensitivity raises recall but also flags its benign novelty/denial decoys: F1 falls from 0.9412 to 0.7500. This regression is reported rather than removed by relabeling or threshold fitting.

The second generator is independently implemented: LCG random source, mesh/hub service graph, outcome synonyms and a distinct attack mix. Seed 314159 gives 3,600 reference + 13,200 evaluated events, covering slow chains, fan-out, session hopping, two-hop success paths, approved benign fan-out, unknown benign novelty and isolated attacks. It retains 200 false-positive and 100 missed events. Both builders inject +/-300-second clock offsets and up to 120-second receipt delay. Neither imports the other's scenario construction or labels.
F1 is event-level. Median alert latency is calculated from supporting receipt timestamps and includes deliberate collection delay; it is not a live streaming or CPU benchmark. Timing uncertainty is retained. A frozen reference can be poisoned if its operator does not review it, and synthetic coverage does not predict real-world attack recall.

## Lease measurement and security scope

Five distinct OS processes use five different encrypted cache databases. Sync delay is injected at 50/150/300 ms; updates are withheld entirely for two nodes. A single observer polls after the central revocation acknowledgement. Polling/scheduling adds delay to the first observed denial (therefore a measured value can slightly exceed L even though the node's authorization check expired on time). The reported maximum is the max of 5 samples, not a population percentile estimate.

Deterministic tests check exact lease cutoff, stale-challenge replay, delayed response, wrong node/authority, tampered snapshot, forked chain, restart and monotonic rollback. The conditional authorization bound is L/(1-rho) under the clock-rate assumption in [the design](TRACK4_DESIGN.md). Nodes do not implement Byzantine consensus and a paused/stopped monotonic clock violates that assumption.

## Other operational boundaries

All routine data operations have explicit capacity limits. Security controls bypass the soft audit budget, but still need functioning durable storage. At-rest encryption protects database-only leakage; the whole state directory contains its master key. External anchors are required to detect known-prefix rollback. Native memory zeroization is not proven. Session resumption is intentionally unsupported. Hidden judge tests, independent cryptographic certification and production-scale accuracy/availability are not claimed.
