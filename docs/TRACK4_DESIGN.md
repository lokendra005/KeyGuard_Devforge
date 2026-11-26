# Track 4: architecture, algorithms and assurance boundaries

This is the protected-file and encrypted-message implementation in `track4/`, not a mock adapter around the Go ledger. The root `track4_service.cjs`, HTTP API, operator CLI and dashboard use the same SQLite authority and policy functions. No organizer event IDs, labels, owners, keys, file contents or expected answers occur in the decision code. Limits and cryptographic domain identifiers are protocol parameters; deployment policy and detector baselines are explicit inputs.

An optional Go/PostgreSQL implementation is isolated under `legacy/`; it is not part of the Node judge path. Source relocation does not migrate deployed keys or state. Its protocol is documented under `legacy/docs/`. Repository history and third-party attribution are retained; eligibility and authorship are not inferred from file placement.

## Components and trust boundaries

```mermaid
flowchart LR
  J[Trusted organizer worker] --> A[One JSON request adapter]
  C[Local ML-DSA signing CLI] --> H[HTTPS signed-command API]
  A --> P[Shared policy and transaction core]
  H --> P
  P --> D[(SQLite authority, files, audit, relay)]
  O[Observer dashboard] --> H
  S[Sender: encrypt locally] --> H
  H --> R[Recipient: decrypt locally]
  L[Trusted logs and approval context] --> E[Deterministic detector]
  E --> P
```

The worker asserts an actor through a trusted local process interface, as required by its contract. **That interface is not exposed over HTTP.** Network commands require ML-DSA-65 possession proofs. Browser observer tokens are read-only, short-lived and checked against current key/identity state on every use. Neither a CLI-supplied actor name nor a dashboard token authorizes administrative mutations by itself.

Node 24.11.1 supplies OpenSSL-backed ML-KEM-768, ML-DSA-65, AES-256-GCM, SHA-384, HMAC, HKDF and scrypt. `node:sqlite` supplies storage. There is no npm dependency installation, model download, hosted API or PostgreSQL requirement on the worker path. This is use of vetted primitives, not a claim of FIPS certification or an independently audited protocol.

## Authority and crash consistency

`BEGIN IMMEDIATE` serializes authentication, current policy, effects, nonce consumption and successful-operation audit insertion. SQLite WAL and `synchronous=FULL` persist the transaction before returning success. Each worker process reopens the same private state directory. Local API/worker processes share the authority. Independent read nodes instead maintain separate encrypted caches and verified signed policy chains, with explicitly bounded stale access as described below. Trusted worker `setup` atomically replaces its scenario tables, generating a new authority/audit identity; malformed replacement rolls back. CLI initialization and network commands cannot invoke this reset.

For a key `k`, authorization at time `t` requires an enabled actor, matching epoch, a registered unrevoked key, `not_before <= t`, and either no cutoff or `t < not_after`. The signature binds version, authority, actor, key fingerprint, epoch, nonce, expiry and complete operation body. The input parser rejects duplicate JSON fields, invalid UTF-8, lone surrogates, excessive nesting and unsafe numbers. Every SQLite-bound string is JSON encoded to preserve opaque identifiers including embedded NULs; this is a storage representation, not normalization of identity.

**Revocation argument.** Let `R` be the commit disabling an identity, and `E` a later protected effect. The exclusive transaction order forces `E` to read the disabled state after `R`; its predicate fails. Consequently there is no authorized effect whose authorization linearizes after `R`, assuming the database, runtime and policy code execute as specified. A response already committed before revocation may arrive later. Previously disclosed plaintext cannot be recalled.

**Atomic rotation.** A new key proves possession over the authority, target actor, current epoch, new public key and requested grace. One transaction installs that key, advances the actor epoch and cuts off every older key at `min(existing_cutoff, now + grace)`. A fresh request using an old key can operate during the declared grace; prior-epoch requests cannot. At the exact cutoff, the old key fails. Audit insertion or disk failure rolls back the whole change. An actual SIGKILL test interrupts an uncommitted rotation and verifies the old consistent version, file content and existing revocation after restart.

**Recovery.** Two distinct current admin/recovery identities approve an identical, expiring replacement proposal. Each approval binds the target epoch and new-key possession proof. The second approval rechecks the first approver's role, key lifetime, revocation and epoch. Completion retires all old target keys, installs the new one and increments the epoch atomically. A competing proposal from the earlier epoch fails. Self-approval is rejected. Recovery requires surviving authorized custodians; it does not solve loss of every administrative key.

Authority time advances from a wall-clock anchor using a monotonic process clock. A transient wall-clock jump cannot poison a running process. Startup still requires time no earlier than the persisted high-water mark; clock repair is required if that trust assumption fails. Request nonces are retained through expiry; protected-read challenge/key/resource tuples have a configurable 120-second replay window. After that window the same opaque worker challenge can be used for a new encapsulation; applications must use fresh unpredictable challenges and reject stale replies. A read correlation ID may be retried for the same actor/resource: every retry checks current policy, the audit lookup retains the first decision, and immutable events retain all subsequent decisions. Reusing the ID for a different actor/resource is rejected. A previous allow result is never an authorization cache.

## Two distinct encryption workflows

### Organizer protected read

After checking file ownership and revocation:

`(ct, ss) = ML-KEM-768.Encaps(pk)`

`proof = hex_lower(HMAC-SHA-256(ss, UTF8(challenge || stored_body)))`

There is **no delimiter** in this organizer-defined concatenation. The public key and ciphertext use raw FIPS 203 representations and standard Base64. The HMAC is deliberately SHA-256 for wire compatibility; it does not change the SHA-384 commitments elsewhere. Independent `pqcrypto==0.4.0` decapsulation validates actual interoperability. This operation is a proof of possession of the encapsulated secret and exact file value, not an end-to-end messaging protocol.

### Client-to-client messages

The recipient generates a one-use ephemeral ML-KEM keypair in memory and signs an offer. It binds both actors, both pinned identity-key fingerprints, authority, offer ID, expiry and ephemeral public key. The sender verifies it against a separately trusted recipient key, encapsulates, and derives an AES-256 key:

`salt = SHA384(canonical(signed_offer))`

`info = SHA384(canonical(["KIG/message-key/v1", binding]))`

`K = HKDF-SHA384(ss, salt, info, 32)`

The binding contains the suite/version, authority, message and offer IDs, both actors/key fingerprints, expiry and KEM ciphertext. AES-256-GCM authenticates the binding as AAD with a fresh random 96-bit nonce. An ML-DSA signature also binds that header, nonce, authentication tag, ciphertext digest, length and chunk count. The receiver verifies the sender before accepting bounded chunks, then verifies the complete ciphertext and AEAD tag before releasing any plaintext.

The sender retries the same ciphertext, not fresh encryptions of a request with an uncertain outcome. The relay merges equal chunks, rejects conflicting chunks/message identities, and checks both peers against current authority. It stores ciphertext, never session secrets. Receivers accept reordered chunks, suppress duplicate chunks and reject a completed offer's reuse. Expired incomplete messages are discarded and report failure. The CLI makes at most five transport attempts; recipient acknowledgement is a separate operation from queue acceptance. There is no claim of exactly-once external file delivery across a crash between local output and acknowledgement.

**Conditional forward secrecy.** Later possession of a long-term signing key does not yield a completed message's ephemeral KEM private key or encapsulated secret. Receiver private KeyObjects are never serialized; references are discarded on completion, failure or close. This claim assumes ML-KEM security, authenticated peer-key pinning, uncompromised endpoints during the exchange, and effective native-runtime/OS cleanup. JavaScript cannot prove physical zeroization of native allocations or swap. No crash-resumable session secrets are saved; after a receiver restart, senders need a fresh offer. Session resumption is intentionally unsupported.

This is an application composition of standard primitives, not TLS/HPKE wire compatibility or a formally verified new cryptographic construction. HKDF transcript hashing is necessary for bounded context length. SHA-384's ideal collision work is approximately 2^192 classically, or 2^128 quantum queries under the usual collision model; these estimates do not prove uniform end-to-end security of the deployment.

## Storage, logs and backups

File encryption authenticates authority, asset, owner and version. The master key is a randomly generated 0600 file in a private 0700 directory; symlink/ownership checks and exclusive, synced installation prevent accidental overwrite or silent key regeneration. Database-only disclosure does not expose file bodies. A compromised host holding the master key is outside this protection.

Each audit event has an explicit sequence and JSON record boundary. Its SHA-384 chain commits to the preceding hash and structured event; an ML-DSA signature authenticates each chain link. Independent verification checks identity key, authority, order, time and optional external prefix anchor. Read allow/deny events commit with their decision records. Rejected signed-command attempts update a bounded 60-minute aggregate counter, not a signed event per request. Counters are operational telemetry, not an individual signed denial trail. The normal event budget defaults to 1,000,000 and can be increased through a signed admin command; reaching it stops ordinary data operations but cannot block revocation, rotation, recovery, role changes or backup. Physical disk/transaction failure still prevents a successful commit. Status verifies the suffix after an in-process verified checkpoint; complete exported history remains independently verifiable. Cached-prefix verification assumes the already checked prefix is retained; it is not a rescan for retroactive disk tampering. This log attests to the trusted authority's reports, not truthfulness of a compromised host or independent replay of client intent. The optional Go ledger's replayable evidence is a separate format.

Identity backups and consistent logical authority snapshots use scrypt-derived AES-GCM encryption with random salt/nonce. Restore authenticates the envelope, validates private/public-key correspondence and file tags, and checks signed audit history against a separately retained anchor. Restore only creates a new directory. A complete older backup cannot pass an anchor that knows a later prefix. An unseen lost suffix cannot be inferred without independent retained knowledge. Snapshots are bounded at 128 MiB; excess size fails explicitly.

## Explainable detection

Inputs carry immutable IDs, required actor/service/action/outcome fields and timezone-qualified timestamps. Optional correlation/session/approval/role/offset fields default to empty or zero; missing receipt time is marked uncertain. RFC3339 numeric offsets and 1-9 fractional digits are supported, with millisecond truncation. Impossible dates, missing timezones and leap seconds are rejected rather than silently guessed. Input budgets remain explicit: batch analysis permits 100,000 events / 64 MiB; the API has a 16-MiB request/response and metadata limit. The 12,000-event holdout fits those API limits. Larger analyses run through the offline CLI or partitioned workloads; unlimited ingestion is not claimed.

A separate, earlier reference window is frozen before evaluation. `learn()` counts successful, stable-role service paths and retains paths with at least two observations, indexed by actor and role. This is a deterministic frequency table, not ML. The report commits to reference data and configuration. Evaluation refuses overlapping reference/holdout windows, and labels are consumed only by `score()`. Reference contamination remains a trust risk; do not train on unreviewed incidents or automatically absorb the evaluated window.

Any successful role-state change is checked regardless of action spelling. Independent approver, subject, target role, validity interval and service scope must match. Self-approved changes and allowed access after an observed identity/role revocation alert. A novel edge alone is a low-confidence label, not an attack verdict; explicit `alert_on_novel` enables a stricter policy if desired.

For lateral movement, events are grouped by identity/session, not correlation ID. Dynamic path tails connect source to prior target with distinct edges in a 300-second window. For a candidate path at time `t`, evidence weight is `S = sum(2^(-(t-ti)/H))`, where default half-life `H=120 seconds`. At least three connected unexpected edges and `S >= 2` trigger an explainable candidate. Three steps spaced 70 seconds apart satisfy this rule. Path tails retain at most 128 edges; only the latest candidate per target is extended, so branching can lose alternate hypotheses. Denied attempts do not establish successful compromise. Missing session IDs group by actor and can merge unrelated sessions; the report retains the original fields for investigation.

Corrected time is `source_time - offset`, with interval `[corrected - uncertainty, corrected + uncertainty]`. Defaults support measured offsets within +/-300 seconds and lateness up to 120 seconds; larger values are marked uncertain. Late prerequisites are processed in corrected order while alert time is the maximum receipt time of supporting observations. This is retrospective analysis, not an online watermark service. `estimateClock` implements the four-timestamp offset/delay calculation; offsets must come from trusted measurements.

The seeded benchmark uses 4,000 reference events and 12,000 later held-out observations, renamed services/actions/roles, skew, late arrivals, benign novelty, isolated denials and attacks. Labels never enter detection. Reported F1 and delay are synthetic event-level metrics, not deployment accuracy; isolated stolen-credential reads remain a known blind spot. Receipt-derived delay includes injected collection lag, not just CPU execution.

## Independent-node lease design and bound

A `replicator` credential may request snapshots but cannot administer identities. The authority signs `version, authority, node ID, challenge, node audit key, lease length, issuance time, checkpoint, audit suffix, policy, identities, keys and file values` under a distinct ML-DSA domain. HTTPS protects the authorized replication channel. Every node pins the authority/audit public key out of band, verifies the contiguous signed chain from its retained checkpoint, persists its own policy log and encrypted snapshot, and runs the same pure command verifier as the authority. Replication credentials and nodes can read their cache's plaintext: they are trusted resource servers, not untrusted ciphertext-only relays.

The node records a fresh challenge at monotonic time `m0`. A valid response must match that challenge and node identity; its deadline is `m0 + L`, never response-arrival time plus L. Delayed, replayed, wrong-node, tampered or forked grants cannot extend a lease. Each read checks lease validity before authorization, before transaction commit and before returning/queuing the response. Restart invalidates every lease until a fresh successful sync. Authentication time uses the authority's signed issuance time plus conservative elapsed time and a persisted high-water mark; local wall-clock changes do not extend grants. All local read decisions have their own signed node log, whose key is bound by the authority's grant.

**Conditional bound.** Let `r` be a committed revocation. Any grant carrying the pre-revocation policy was issued before `r`, and its challenge started no later than its issuance. If the node's monotonic clock progresses at rate at least `1-rho` relative to real time, that grant expires no later than `r + L/(1-rho)`. A newer grant either includes revocation or the node fails closed. Thus no new read authorization using the revoked credential occurs after this bound. With `rho=0`, it is at most L, including a total network partition. The requested `Delta+L` bound is a looser consequence; it is not evidence that a network message propagates through a partition. Normal connected convergence additionally depends on sync period, network delay and scheduling.

The bound concerns authorization/response queueing, not the time already-buffered bytes reach a remote recipient. It assumes an uncompromised authority/node and a monotonic clock that advances through suspension at the stated rate. A paused VM whose clock stops violates that assumption. Host wall-clock or measurement uncertainty, physical WAN behavior, Byzantine authorities, hardware clock certification and real-time scheduling are not proven. The five-process benchmark delays three sync transports and withholds two entirely; all five use different databases. Its p50/p99/max are five observed samples with polling delay, not a production SLA.

## Review scope and references

Tests exercise malformed encodings, actual process boundaries, key migration races, lost/reordered messages, tamper, corruption, current-policy checks, a real crash, independent KEM decapsulation and CLI/HTTP delivery. These are executable evidence and conditional arguments, not a mathematical proof of every code path. The authority and each independent cache require a supported local filesystem. Network-filesystem WAL, Byzantine replication, endpoint memory forensics, unrestricted DDoS resistance and physical key custody are outside scope.

Primary implementation references: [Node 24.11.1 crypto](https://nodejs.org/download/release/v24.11.1/docs/api/crypto.html), [Node SQLite](https://nodejs.org/download/release/v24.11.1/docs/api/sqlite.html), [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). The organizer wire contract is pinned to [toolkit commit 8901dfb](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit/blob/8901dfbdbfe048853e0bfa25b60583d1e6617a63/docs/adapter-v1.md).
