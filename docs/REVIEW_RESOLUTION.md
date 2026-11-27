# Security review resolution

The supplied review was used as an adversarial checklist. Changes were made in the shared implementation, with executable regressions; proposed shortcuts were adjusted where they weakened the boundary.

| Finding | Resolution and evidence |
|---|---|
| Repeated worker setup retained the old scenario | Adapter-only atomic SQL reset, new authority/audit identity, rollback on malformed setup, and stale-process fencing. No recursive deletion of an operator directory. CLI/network initialization cannot reset. `review.test.cjs`. |
| Expected worker errors exited as crashes; omitted disabled list | Expected input/policy errors return JSON with exit 0; absent `disabled` defaults to empty. Unexpected internal/storage failures remain nonzero. Real subprocess tests cover setup/read/audit/revoke/malformed input. |
| Forged requests exhausted audit capacity and blocked revoke | Bounded minute counters replace per-attempt signatures; normal budget is configurable. Revocation, rotation, recovery, role changes, budget increases and backup bypass the soft limit but still require a durable commit. Both 75 direct forgeries and 50 actual HTTP requests leave the signed log uninflated. |
| Status repeatedly verified all history | A cached verified checkpoint anchors suffix validation. Full export verification remains available. The cache is not a retrospective rescan for tampering in an already verified prefix. |
| Detector tied to practice names/actions | Separate frozen reference baseline, action-independent role transitions, independent-approver checks, identity/role revocation, legitimate regrant handling, and actor-wide graph grouping with time decay. Novelty alone is not an attack alert. |
| Input diversity and 10k limit | Numeric timezone offsets and up to nine fractional timestamp digits; optional fields default; impossible/ambiguous dates fail explicitly. 100k-event / 64-MiB offline analysis budget replaces 10k. An actual signed API test persists 10,020 events. API transport/metadata budgets remain 16 MiB, not unlimited. |
| Missing generalization measurements | 4,000 reference + 12,000 disjoint held-out events with renamed identities/services/roles/actions, skew, late arrival and decoys. Labels only enter scoring. Both the original holdout and an independently implemented topology holdout report their measured false positives and misses. A second renamed seed is also committed. |
| Shared-file nodes avoided distribution | Independent encrypted node databases, retained signed policy chains, authority-pinned snapshots and fresh-challenge leases. Real five-process delay/partition measurement plus an actual HTTP sync test. Bound assumes a progressing monotonic clock; no Byzantine-consensus or WAN SLA claim. |
| Rotation deleted in-flight offers | Offers survive through valid grace. Delivery/poll recheck old-key cutoff. Expired-key offers no longer shadow replacement offers or consume that recipient's new-offer quota. |
| Anonymous identity enumeration | Public context contains no actor metadata. Identity bootstrap requires a fresh possession proof; anonymous known/unknown lookups receive the same denial. Cross-actor reads require privileges. |
| One actor could consume the relay | Per-actor offer/sender/recipient quotas supplement global limits. Only admin enrollment can add identities. |
| Correlation reuse changed the original decision | `audit(request_id)` preserves the first decision; every retry still checks current policy and appends its own immutable event. Different actor/resource reuse is rejected. |
| Protected-read replay records never expired | Finite configurable replay window, default 120 seconds. Clients must generate fresh challenges; the opaque worker contract has no challenge timestamp. A new encapsulation after that window is explicitly permitted. |
| Transient forward clock jump poisoned state | Process time advances monotonically from its startup wall-clock anchor. Later wall-clock jumps do not change it. Startup before the persisted high-water mark still fails closed; clock repair is required in that case. |
| Master key beside database | Explicitly documented in README, design and threat-model PDF: at-rest encryption protects database-only leakage, not whole-state-directory theft. |
| Root container build needed ignored dist files | Root Dockerfile builds directly from Node source. Optional Go code/build/docs moved intact under `legacy/`; repository history is retained. The moved Go build was checked. |
| Evidence unavailable in repository | Actual logs, metrics and regeneration scripts are committed under `evidence/`; offline images and reviewer bundle are release assets. |
| Missing brief/video and public access | Two-page PDF and narrated 300-second recorded-evidence video are provided with release links. Public repository/asset access is checked after publication and recorded with the release. |
| SQLite stderr noise | Only its exact ExperimentalWarning is filtered during import. An executable test proves unrelated warnings remain visible. |

## Limits deliberately retained

- Input, memory, storage, relay and backup limits remain explicit. Removing all bounds would create denial-of-service risks. A 128-MiB full-backup ceiling and 16-MiB API response limit remain operational constraints; no large-scale SLA is claimed.
- The detector is retrospective and deterministic. Its actor-wide graph can flag legitimate unknown fan-out; reviewed baselines/approvals are needed. Reviewed reference data, trustworthy logs and clock metadata are required.
- Lease expiry deliberately reduces availability during partitions. Monotonic-clock suspension/drift assumptions are stated; a paused VM whose clock stops does not satisfy the bound.
- Session resumption and provable physical memory erasure are not implemented. Independent audit and hidden judge tests are unavailable.
- Moving optional source and removing conversational notes does not alter provenance, authorship or hackathon eligibility. No history was rewritten to imply a different creation date.

## Follow-up review: protocol v2

- Outcome synonym configuration, exact-event deduplication, conflicting-duplicate errors, actor-wide graphs, fan-out, slower windows and successful two-hop evidence are implemented in the shared detector. A separately written topology generator supplements the original unchanged holdout; both confusion matrices are published, including the increased false positives.
- Every sync is audited, requires a one-node/key-bound replicator and caps its lease. Admin sync is forbidden. Signed node read chains upload with retry-safe acknowledgements, are queryable by audit, and enter detection. Snapshots use verified full/delta mode and exact base checkpoints.
- v2 signed audiences prevent authority/node and cross-node replay. Clients discover the target audience; old unsigned-audience envelopes fail closed.
- Per-IP concurrency and five-second header/body deadlines are exercised with real trickling clients.
- Unowned assets use NULL ownership and deny access. Plaintext UTF-8 bytes determine storage usage.
- Persisted signed verification checkpoints accelerate cold startup; complete evidence verification and independent rollback anchors remain available. Read indexes bind their original signed event, including a signature that prevents substitution with a later event.
- Migration/restart tests preserve authority keys, ciphertext and event history; node caches merge deltas across restart but never restore leases.

## Precision follow-up: detector report v3

Two successful edges now need a directed, interval-ordered three-service pivot to invoke the two-hop shortcut. Three-edge undirected fan-out keeps its existing score/count thresholds. Trusted prior baseline successes establish window-bounded familiarity for the same actor and route; this affects movement evidence only, never authorization or independent role/revocation findings. The sweep index is checked against exhaustive search. Both holdout generators remain byte-identical to review-v3, and 20 comparisons preserve all previously detected attack events while reducing false positives. Full mathematics, measurements and ambiguity limits are in [DETECTOR_PRECISION.md](DETECTOR_PRECISION.md).
