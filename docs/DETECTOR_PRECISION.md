# Detector precision: structural changes, unchanged thresholds

The review-v4 detector report is version 3; network commands remain version 2. This changes retrospective detection only. Keys, policy enforcement, stored events and baseline format are unchanged. API ingestion recomputes a report from retained observations with the same shared detector as the CLI. Previously saved reports remain historical until the next ingestion.

## Two spokes are not two hops

An undirected component of two edges can be a pivot, two outgoing spokes, two incoming spokes, or a backwards-in-time path. Only the first justifies the special two-successful-hop shortcut. The general three-edge undirected rule still catches fan-out, reversed edges and mixed failed/successful attempts across sessions.

For successful, reliable observations e1=(A,B,t1,u1) and e2=(B,C,t2,u2), the shortcut requires:

- One actor, three distinct services, and both edges unusual.
- `t1 + u1 < t2 - u2`: the first time interval strictly precedes the second.
- `t2 - t1 <= window_ms`: both corrected timestamps fit the same window.

A candidate emits only the two supporting events. Unrelated spokes do not become evidence merely because they share a vertex. The three-edge rule retains its complete connected-component evidence. Unknown outcomes, unreliable timing, ties and overlapping uncertainty intervals cannot establish a confirmed two-hop witness; they remain observations and may still satisfy the general three-edge rule.

**Index correctness.** Sort candidate second hops by earliest time and first hops by latest time. Activate a first hop only after its latest time strictly precedes the query's earliest time. Index activated hops by `(actor, destination)`. Within each index, keep the two greatest corrected times with distinct origins. A query excludes only one origin (its own destination), so the newest eligible origin is always among these two. If that candidate is outside the window, every older candidate is too. This is equivalent to exhaustive existential search under these conditions. It takes O(n log n) sorting, O(n) sweep work and O(n) memory; it retains older eligible witnesses even when a more recent repeat overlaps the query's uncertainty interval.

The independent regression oracle checks this result against exhaustive search across 4,000 generated observations, including expiry, repeat edges, distinct actors, cycles, failures and variable uncertainty. This is an algorithmic argument with executable checks, not a proof that every real-world attack is observable.

## Familiarity is different from authorization

A changed role can make an edge absent from that role's reference even though this actor has just used exactly the same route under a trusted baseline. Treating it as a newly reached service can combine unrelated earlier novelty with a later privilege violation.

A route is familiar only when this same actor previously completed the same directed edge, the earlier observation matched the frozen baseline or explicit operator edge policy, it had reliable timing and no independent alerts, the current observation also has reliable timing, its latest possible time precedes the current earliest possible time, and it is within the unchanged movement window. Only the most recent such reference observation is retained; ambiguous newer context conservatively prevents suppression. An arbitrary novel success cannot certify itself or another novel route. Failed, suspicious, other-actor and expired observations cannot create familiarity. Temporary scope approvals do not automatically train this index.

Familiarity excludes an edge from the **movement graph only**. Role-change, self-approval, revocation, scope-violation and explicit strict-novelty rules execute first and retain their alerts. The event remains in the report with `novel_service_path`, `familiar_actor_path` and `route_context_event_id` linking the earlier context. This does not grant access or modify any baseline, permission, approval or key.

## Evaluation and limits

No window, half-life, count threshold, score threshold, outcome vocabulary, holdout scenario or label changed. Both generator files are byte-for-byte identical to review-v3. The algorithm uses no event-name prefixes, scenario names, labels or benchmark seed branches. Regression fixtures check renamed services, adversarial labels and receipt-order permutations.

| Event-level holdout | review-v3 | review-v4 |
|---|---|---|
| Original | TP 1080, FP 720, FN 0; F1 0.7500 | TP 1080, FP 240, FN 0; F1 0.9000 |
| Independent topology | TP 1300, FP 200, FN 100; F1 0.8966 | TP 1300, FP 0, FN 100; F1 0.9630 |

Ten fixed seeds per generator repeat the comparison. Every previously detected attack event is still detected in all 20 runs. Seeds vary names, vocabulary and timing within the same two scenario families; they are not 20 independent real-world datasets. Slow chains, three-or-more-edge fan-out, session hopping and successful ordered two-hop paths also have direct label-free regression assertions.

The original holdout's remaining 240 false-positive events are retained. An unusual three-edge fan-out can be benign or malicious with identical observable fields. No deterministic detector can distinguish identical inputs based on intent. Additional trusted approvals, endpoint provenance or operator context would be needed; inventing exemptions from labels would only conceal this ambiguity. The second holdout's 100 isolated attacks remain missed. A malicious two-spoke pattern is intentionally no longer called a confirmed two-hop pivot. This is not universal recall preservation.

Run both existing generators and `node --test track4/test/detect*.test.cjs`. To reproduce the before/after comparison, use a separately retained review-v3 checkout: `node track4/test/detector-comparison.cjs /path/to/review-v3`. It verifies both generator files match, emits all metrics, and fails if a previously detected labeled attack disappears or false positives increase. No earlier checkout is needed for the offline regression suite. Committed comparison evidence is in `evidence/detector-precision-validation.json`.

## review-v5 robustness update

Both holdout results are unchanged (F1 0.9000 and 0.9630). Changes, each with a regression test:

- **Organizer practice set** (`track4/test/fixtures/practice`, copied unchanged from the toolkit): all five labelled findings alert and nothing else does. An operator acting on an approval it issued (approve/revoke administration, `approved_by === actor`, `subject !== actor`) is labelled `approval_administration`, not a scope violation; it still earns no route trust.
- **Unknown outcomes** are counted (`counts.unknown_outcome`, label `unknown_outcome`). On a role transition they are evaluated as success, so an unrecognized word cannot hide an unapproved escalation.
- **Quarantine instead of abort.** A malformed record, a conflicting duplicate `event_id` (first copy kept), or a record inside the baseline window is listed in `rejected`; malformed or conflicting approvals are listed in `rejected_approvals` and authorize nothing. `strict_input: true` restores fail-fast behaviour. A holdout that overlaps the baseline entirely is still refused. Scoring counts quarantined labelled records as not alerted.
- **Revocation state** is keyed by `subject`; without one only `identity_state_after` describes the actor. `enable_user`/`reinstate`/`restore_user` or `identity_state_after: active` clears it.
- **Cross-identity pivots** (`cross_identity_window_ms`, default 300000; 0 disables): identity X successfully reaches B over an unusual edge, then identity Y successfully leaves B for a third service, with provable order. Alerts name every identity (`identities`) and merge per pivot service while hops keep arriving.
- **Missing receipt time** no longer disables ordered pivots when event-time intervals still prove the order; contradictory timing (event after receipt, offset above `max_offset_ms`, lateness) still does.
- **Incidents survive rebuilds.** Incident state lives on rows, so expiry rebuilds and component merges extend the existing alert instead of opening a new one per event. Above 512 live edges per actor, rebuilds are amortized (components may briefly keep up to 12.5% expired edges). One identity with 100,000 unusual edges across 2,000 services: about 1.3 s, 180 MB, a few hundred incidents (previously out of memory).

Remaining blind spots: hops further apart than the 30-minute window, and pivots whose recorded source offset exceeds `max_offset_ms`.
