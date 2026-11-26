# Key Identity Guard mathematical assurance

Key Identity Guard's strongest submission is a **precisely specified post-quantum authorization protocol**, with independent cryptographic vectors and executable checks of its state invariants. The core already performs actual ML-DSA-65 signing and verification; it is not an input/output classifier or a simulated quantum circuit. The important research question is whether that primitive, request encoding, revocation, recovery and audit history compose into the properties the track asks for. This document derives those properties, identifies their assumptions, connects them to the implementation and distinguishes completed work from proposed upgrades. **The whole application is not claimed to have uniform NIST category 3 security:** legacy v1 evidence retains its SHA-256 boundary. The implemented v2 suite uses SHA-384 commitments for new work and explicitly seals the unchanged legacy prefix at cutover. Neither the security of lattice problems nor every execution of the Go/SQL implementation has been proved unconditionally.

Research reviewed on 26 November 2026; SHA-384 implementation updated on 27 November 2026. See [the implemented v2 protocol and operator migration procedure](PROTOCOL_V2.md). The executable and vector results accompanying the reviewer archive are the evidence for that particular build; the mathematical arguments below are not a substitute for executing them.

## The requirement is compromise-resistant authorization using post-quantum signatures

The supplied two-page DevForge overview identifies Track 4 with “Post-Quantum Cryptography and Zero-Trust Identity Controls.” It describes mock services, synthetic identities, sensitive workflows, changing access and verifiable telemetry under identity or key compromise. It refers to a separate details tab that is not contained in the supplied PDF. Nothing in that overview establishes a requirement for quantum hardware, quantum key distribution, an invented signature scheme or a particular formal-verification language. The precise hidden evaluator contract remains unavailable. The source is the user-supplied `Yugaantar DevForge Tracks.pdf`; the earlier research report records the same scope.

Post-quantum cryptography runs on ordinary computers and targets attacks by future quantum computers. ML-DSA is a standardized lattice signature scheme, and ML-DSA-65 is assigned category 3. These are computational security claims, not proofs that no attack can ever exist. ([NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))

Possession of a signing key and current authority to perform an action are different predicates. A stolen key can produce signatures indistinguishable from the legitimate owner's signatures. No verifier, quantum or classical, can recover the owner's intent from identical valid transcripts. The system therefore needs an independent incident signal, followed by an atomic authority change. Zero trust's focus on identity and resources supports this separation; it does not mean that the enforcement server itself is outside the trusted computing base. ([NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final))

The contribution is the composition in the following table. Its value should be judged by the exact attack it prevents and the evidence supporting that claim, not by the number of cryptographic acronyms.

| Mechanism | Implemented property | Important boundary |
|---|---|---|
| ML-DSA-65 with distinct contexts | Authenticate the signed envelope using a standardized post-quantum primitive | A compromised key still signs successfully |
| Fixed-order, length-prefixed fields and exact body commitment | Bind audience, operation, action, resources, versions, expiry and exact body bytes | v2 uses SHA-384; legacy v1 signatures retain their original bound |
| Current authority under a database row lock | Prevent new old-key effects after revocation commits | Assumes trusted executable and primary database; protects the local transaction |
| Distinct recovery approvers plus target epoch | Prevent one approver counting twice and stale approval completing after an authority change | Two-person authorization, not threshold ML-DSA |
| Persistent operation records and consumed challenges | At most one new effect for the same subject/operation | An uncertain response does not imply the transaction failed |
| Signed replayable history and retained witness prefix | Detect inconsistency with history independently retained by the verifier | Does not prove freshness without an anchor or truthful behavior by a malicious executor |

The current primitive is CIRCL v1.6.5, pinned and vendored. Its use is a deliberate engineering decision: preserve a reviewed public algorithm and make the application protocol small enough to inspect. No independent audit or FIPS validation of this application is claimed. The implementation is in [protocol.go](../internal/guard/protocol.go), [state.go](../internal/guard/state.go), [store.go](../internal/guard/store.go) and [audit.go](../internal/guard/audit.go).

## The lattice arithmetic is real, and correctness has a concrete derivation

### The ring and parameter choices determine the implementation

The following notation describes the vendored implementation, rather than a new cryptographic construction. Arithmetic takes place in

\[
R_q=\mathbb Z_q[X]/(X^{256}+1),\qquad q=8\,380\,417.
\]

A vector entry is a polynomial with 256 coefficients; multiplication is negacyclic polynomial multiplication modulo \(q\). The matrix \(A\in R_q^{6\times5}\) is expanded deterministically from a public seed \(\rho\). Secret vectors are \(s_1\in R_q^5\) and \(s_2\in R_q^6\). The infinity norm below is the maximum absolute value of the relevant centered coefficients.

| Parameter | ML-DSA-65 value | Role in the algorithm |
|---|---:|---|
| \(n\) | 256 | Coefficients per polynomial |
| \((k,\ell)\) | (6, 5) | Matrix and vector dimensions |
| \(\eta\) | 4 | Secret coefficients lie in \([-4,4]\) |
| \(\tau\) | 49 | Nonzero coefficients in the challenge polynomial |
| \(\beta=\tau\eta\) | 196 | Bound on challenge times a small secret |
| \(d\) | 13 | Public-key rounding exponent |
| \(\gamma_1\) | 524,288 | Response/mask range parameter |
| \(\gamma_2\) | 261,888 | High/low decomposition parameter |
| \(\omega\) | 55 | Maximum hint weight |
| Challenge digest length | 48 bytes | Encoded Fiat-Shamir challenge |
| Public-key hash and message representative | 64 bytes each | SHAKE256 outputs used internally |

These values can be inspected without internet access in [params.go](../vendor/github.com/cloudflare/circl/sign/mldsa/mldsa65/internal/params.go) and the [vendored arithmetic](../vendor/github.com/cloudflare/circl/sign/mldsa/mldsa65/internal/dilithium.go). The public key is 1,952 bytes, expanded private key 4,032 bytes and signature 3,309 bytes. The sizes are structurally meaningful: the signature is \(48+5\cdot640+(55+6)=3309\) bytes, comprising the challenge, five packed response polynomials and sparse hints. A parser accepting arbitrary extra bytes would change the defined language of signatures.

The implementation accelerates polynomial multiplication with the number theoretic transform. Since \(q-1=512\cdot16368\), the modulus supports the roots needed for this negacyclic transform. This is finite-field arithmetic, not floating-point approximation. The historical Dilithium design explains the choice of uniform sampling and rejection over discrete-Gaussian sampling; final ML-DSA encodings and vectors must nevertheless come from the final standard, not an older Dilithium round. ([Dilithium design specification](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf))

### Key generation commits to a noisy module relation

The public relation is

\[
t=A s_1+s_2\pmod q,
\qquad t=2^{13}t_1+t_0\pmod q.
\]

The public key encodes \((\rho,t_1)\); the private key retains the small secrets, low rounding component \(t_0\), signing seed material and a public-key hash. Publishing only the rounded relation saves bytes while leaving verification possible through the hint mechanism. The private seed material is not a password and must come from the operating system's cryptographic random generator.

The correctness relation is not itself a hardness proof. In particular, testing that a public and private key agree does not establish that no attacker can solve for a useful secret. It establishes that this particular key object has the expected algebraic relationship.

### Signing binds the exact message and rejects unsafe candidates

For exact message bytes \(M\) and a context of at most 255 bytes, pure ML-DSA formats the input as

\[
M'=00\,\|\,\operatorname{byte}(|ctx|)\,\|\,ctx\,\|\,M,
\]

\[
tr=\operatorname{SHAKE256}(pk,64),\quad
\mu=\operatorname{SHAKE256}(tr\|M',64),\quad
\rho''=\operatorname{SHAKE256}(K\|rnd\|\mu,64).
\]

Lengths in these SHAKE expressions are bytes. Production signing uses fresh 32-byte \(rnd\); the deterministic mode used for known-answer tests sets the standardized deterministic randomness. The application uses pure ML-DSA over its envelope, **not HashML-DSA**. Hashing the action body inside that envelope is a separate application commitment.

The signer samples a bounded mask vector \(y\), computes \(w=Ay\), extracts its high part \(w_1\), and forms

\[
\widetilde c=\operatorname{SHAKE256}(\mu\|\operatorname{encode}(w_1),48),
\quad c=\operatorname{SampleInBall}(\widetilde c),
\quad z=y+c s_1.
\]

The challenge has exactly 49 nonzero coefficients, each \(+1\) or \(-1\). Therefore every coefficient of \(cs_1\), before modular representation, is a signed sum of at most 49 values of magnitude at most 4. The triangle inequality gives \(\|cs_1\|_\infty\le196\); the same bound holds for \(cs_2\). This explains the parameter \(\beta\), rather than treating it as a magic constant.

The signer rejects a candidate unless the response and rounding conditions hold, including

\[
\|z\|_\infty<524092,
\quad\|\operatorname{LowBits}(w-cs_2)\|_\infty<261692,
\quad\|ct_0\|_\infty<261888,
\quad\operatorname{weight}(h)\le55.
\]

The first two numeric limits are \(\gamma_1-\beta\) and \(\gamma_2-\beta\). These checks control the accepted response distribution and permit correct high-part reconstruction. Removing a rejection check to accelerate a benchmark changes the security argument. The output is \((\widetilde c,z,h)\); the mask and small secret vectors are not transmitted. The corresponding code is the bounded rejection loop in [CIRCL SignTo](../vendor/github.com/cloudflare/circl/sign/mldsa/mldsa65/internal/dilithium.go).

### Verification reconstructs the challenge without the secret

The verifier recomputes the challenge polynomial and evaluates

\[
\begin{aligned}
u&=Az-c(2^{13}t_1)\\
 &=A(y+cs_1)-c(As_1+s_2-t_0)\\
 &=Ay-cs_2+ct_0\pmod q.
\end{aligned}
\]

The hints and signing bounds allow \(\operatorname{UseHint}(h,u)\) to recover the same \(w_1\). Verification hashes that reconstruction with \(\mu\), then requires equality with \(\widetilde c\), a valid response norm and canonical signature encoding. This algebra proves why an honestly generated signature can verify, conditional on the specified arithmetic, decomposition and encoding functions. It does not prove that producing a new accepting tuple is infeasible.

Canonical hints matter. Hint endpoints must not decrease; indices within a polynomial must be strictly increasing; unused padding must be zero. A polynomial with no hints is valid, so equal adjacent endpoints must not be rejected merely for being equal. Both the valid and invalid boundaries need tests; “reject anything unusual” is not a correct verifier.

### A security reduction is different from a correctness derivation

FIPS 204 discusses Module-LWE and SelfTargetMSIS assumptions. Its category is an attack-cost category, not an unconditional statement of “192 quantum bits.” The appropriate claim is resistance under the stated assumptions and security models. ([FIPS 204, security discussion](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf))

An unforgeability game gives an adversary public keys and allowed signing queries, then asks it to produce an accepting signature for a new message/context pair. A proof must specify the oracle model, which keys can be corrupted, query bounds and the reduction loss. After an ordinary signing key is stolen, unforgeability for that key is no longer the mechanism that protects the application; revocation and current-state policy are.

This distinction has practical research support. Barbosa and coauthors repaired a gap in Fiat-Shamir-with-aborts proofs and mechanized a ROM proof in EasyCrypt. Their work supports careful statements about the modeled scheme; it does not certify this Go binary. Jackson, Miller and Wang study a QROM reduction involving SelfTargetMSIS and MLWE under specified parameter conditions. Their analysis does not justify silently replacing all standardized-parameter assumptions with a tight MLWE-only claim. ([Barbosa et al., 2023](https://eprint.iacr.org/2023/246); [Jackson, Miller and Wang, EUROCRYPT 2024](https://www.nist.gov/publications/evaluating-security-crystals-dilithium-quantum-random-oracle-model))

## The application guarantees follow from explicit transition invariants

### Define the trusted state and the acceptance predicate

Let \(S_i\) be the authority state before the \(i\)-th committed protected transition. Failed transactions do not appear in this sequence. Let \(r_i\) include the envelope, exact body bytes and signature, and let \(t_i\) be the primary database time observed under the authority lock. The transition is

\[
S_{i+1}=T(S_i,r_i,t_i).
\]

For a new effect, the acceptance predicate is the conjunction of well-formed encoding, correct audience/version/algorithm, matching body commitment, current key and subject activity, current role permission, valid action signature, unexpired request, matching unused challenge, and the action's state-specific preconditions. A matching already-committed retry follows a distinct branch: it returns the retained result after current authorization/signature checks, without another protected transition.

The proof assumptions are correct application execution, correct PostgreSQL primary transaction semantics, trusted bootstrap and clock behavior, secure randomness, unambiguous bounded encoding, signature unforgeability for uncompromised keys, and the binding properties needed for each hash use. Witness claims additionally require an independently retained trusted checkpoint. A hostile database superuser or modified server executable is outside the enforcement proof; cryptographic evidence has narrower value under those threats.

### Length-prefix encoding prevents a class of substitution ambiguity

For a fixed tuple \((v_1,\ldots,v_m)\), encode each string as its four-byte big-endian length followed by its bytes. Within the permitted domain \(|v_j|<2^{32}\), decoding the next length determines exactly where the next field begins. Induction over the fixed field count shows that equal encodings imply equal tuples. Thus `("ab","c")` and `("a","bc")` cannot have the same encoding, unlike plain concatenation.

The implementation additionally rejects unknown/duplicate JSON fields, semantic field-name aliases, null scalar substitutions, invalid UTF-8 and unbounded inputs. JSON is transport; it is not the canonical signing grammar. Signature contexts separate action, challenge, enrollment, checkpoint and witness messages. This removes structural ambiguity; it does not eliminate the collision assumption for a field containing a hash rather than the full original value. See [protocol.go](../internal/guard/protocol.go) and [json_shape.go](../internal/guard/json_shape.go).

### Revocation safety is an ordering theorem

All protected effects take the exclusive lock on `kig_authority(id=1)` before reading current authority, and retain it through the effect, operation record, challenge consumption and audit insertion. Under READ COMMITTED, a waiter locking an updated row observes the committed updated row. The transaction therefore supplies a serialization point for these authority-critical sections. ([PostgreSQL isolation](https://www.postgresql.org/docs/16/transaction-iso.html); [PostgreSQL row locks](https://www.postgresql.org/docs/16/explicit-locking.html))

Suppose revocation \(R(k)\) commits before a new protected effect \(E(k)\) authenticated by that old key. The effect's critical section must read the revoked bit, since otherwise it would have held the lock before revocation could commit. `Actor` rejects a revoked key. This contradicts acceptance of \(E(k)\). Recovery does not clear any old revoked bit, so induction extends the argument across later recoveries. **An action that acquired the lock and committed before revocation remains possible**, even if its response arrives later. Arrival order and response order are not the security boundary.

This argument applies to the local database effect. Moving the actual effect to an external banking API, queue consumer or other service would introduce another ordering problem. The current proof must not be retained unchanged after such a modification.

### Idempotency and challenges establish at-most-once effects

Let \(O=H(\operatorname{encode}(subject,operation))\). On the first successful request, the effect, consumed challenge, operation digest/result and event become durable in one transaction. A subsequent request for \(O\) either matches the stored digest and returns its result, or fails with a conflict. No second `Apply` is performed. Rollback removes all those changes together, so induction over serialized commits gives at most one new effect per subject/operation, under the hash-binding assumption.

This is not a promise of exactly-once message delivery. If a response is lost after commit, the client must retry the exact persisted request. Inventing a new operation identifier asks for a new operation. A retry after revocation can be denied because current authorization is intentionally checked before the result cache. The relevant implementation is [Store.Execute](../internal/guard/store.go).

### Epoch-fenced recovery rejects stale joint authority

For target subject \(s\), let \(e(s)\) be its monotonically increasing authority epoch. Quarantine, target-key revocation, role change and completed recovery advance it. The first approval records both a digest of the recovery proposal and \(e_0=e(s)\). The second approval requires the same proposal, a distinct active recovery identity, an unexpired proposal and

\[
e_0=e(s).
\]

An intervening authority change makes the equality false. A completed recovery advances the epoch and revokes all prior target keys. Consequently two competing proposals first approved in the same epoch cannot both complete. A role change followed by a change back still advances the epoch; comparing only the final role would miss that history. The target's proof of possession binds the replacement public key but does not establish which human owns it.

This is a two-person policy over two full signatures, not a threshold-signature construction. The guarantee assumes independent approval custody. One compromised recovery root can deny service by quarantining or revoking ordinary targets; two compromised roots can authorize replacement keys. Recovery roots themselves are protected from the ordinary online revoke/recovery operations. That is a current boundary requiring a separate trust-root rotation design, not a solved edge case.

### Integer conservation and monotone time have small proofs

For a transfer of \(a\) from \(x\) to distinct \(y\), require

\[
0<a\le M,\quad x\ge a,\quad y\le M-a,\quad M=10^{12},
\]

and exact source/destination version matches. The updates \(x'=x-a\), \(y'=y+a\) satisfy \(x'+y'=x+y\) and remain within \([0,M]\). All intermediate values are safely within int64 bounds. Resource creation is explicit authorized issuance and is outside this conservation statement. No floating-point tolerance is needed.

The stored last time is a lower bound for the next accepted authority transaction. A backward clock reading causes failure before the callback. This prevents acceptance under a regressed local time but does not provide a distributed time oracle or guarantee availability when the clock is broken. These properties are in [State.Apply](../internal/guard/state.go) and [Store.transaction](../internal/guard/store.go).

### Audit coupling provides evidence consistency, not omniscience

If event insertion fails, the database rolls back the effect and idempotency changes. Each successful protected commit therefore has an event under the database-integrity assumption. The RFC6962-style tree hashes leaves and internal nodes with different prefixes. A signed checkpoint binds the audience, tree size and root. An independently retained checkpoint constrains any later accepted history to contain the same prefix. ([RFC 9162 tree construction](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1))

The offline verifier checks signatures, event ordering, expiry, challenge uniqueness and the replayed results. It does not prove the earlier issuance of each challenge, because challenge issuance is not in the exported event history. It also does not provide complete signed telemetry of rejected HTTP requests. Replay shares the production transition function, which avoids divergent semantics but is not an independent policy oracle. A retained prefix cannot reveal an unobserved suffix, and one witness does not supply global fork gossip or Byzantine consensus.

### Legacy SHA-256 explains the v2 commitment upgrade

In legacy v1, the signature protects the envelope, but the body is represented there by `SHA256(body)`. New v2 requests use `SHA384(body)` and a signed SHA-384 commitment to the full public key. A chosen pair of distinct permitted bodies with the same hash would reuse that binding without a new ML-DSA forgery. Replacing an already fixed body is a second-preimage problem; preparing a pair before asking for a signature is a collision problem. Those are different attack games.

Idealized quantum target search has square-root query scaling, while generic collision finding has cube-root scaling. For a 256-bit ideal output, the corresponding exponents are approximately 128 and \(256/3\). These are query-model comparisons, not practical quantum computer cost estimates, and do not establish an actual attack against this service. They do establish why “SHA-256 gives 128 quantum bits for everything” is an incorrect blanket statement. ([Grover](https://arxiv.org/abs/quant-ph/9605043); [Brassard, Høyer and Tapp](https://arxiv.org/abs/quant-ph/9705002))

NIST's category 2 reference includes 256-bit hash collision search, whereas category 3 references AES-192 key search. FIPS 204 also requires an application-level prehash to retain the selected strength; a 192-bit classical collision target needs at least 384 digest bits. KIG's pure-signature envelope is not HashML-DSA, but its body commitment has the same composition concern. **The version distinction is essential: ML-DSA-65 with SHA-384 v2 commitments, with unchanged SHA-256 v1 historical evidence. This does not establish a uniform category for the whole deployment.** ([NIST categories](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29); [FIPS 204, section 5.4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf))

A schematic security decomposition is

\[
\Pr[\text{unauthorized accepted effect}]
\le \operatorname{Adv}_{signature}
+\operatorname{Adv}_{binding}
+\Pr[\text{policy or trusted-execution assumptions fail}].
\]

This is a way to identify separate obligations, not a tight reduction with concrete query bounds. Compromised-key revocation needs the transition invariant even when the corresponding signature term no longer offers protection.

## Offline evidence must test the mathematics independently

### Known answers exercise the final-standard interface

Randomly generating a key, signing with it and verifying with the same library is useful but can miss a shared implementation mistake. The offline suite therefore uses pinned external known answers. Key generation compares exact public and expanded-private bytes. Deterministic external pure signature generation compares exact signature bytes. Verification tests both acceptance and rejection. The input interface matters: feeding an internal preformatted message to an external API would add the context prefix twice. ([NIST ACVP ML-DSA protocol](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html))

NIST sample vectors and Wycheproof adversarial cases are fixtures, not network services. [Fixture provenance](../internal/guard/testdata/README.md) records NIST commit `975de31eb83d87039ec88934fdc47d8c312b892d` and Wycheproof commit `65ca494727a52944c204441c860b039e6786b99b`. Exact upstream URLs and file hashes are retained inside the corpus, and the offline import script reproduces the selection. Deterministic vector signing is a conformance check; production remains randomized. The optional independent OpenSSL check exercises both signing directions with context binding. The mandatory embedded fixtures run even when an offline review image has no suitable OpenSSL installation. Passing those cases is not ACVP certification.

`TestIndependentMLDSAVectors` passed the focused build check with **25 exact public/private key-generation answers, 15 exact deterministic signature answers, verification of all 30 NIST signature-generation outputs, and 225 independent verification cases: 82 accepted and 143 rejected**. The 225 cases include 15 NIST cases and the entire pinned 210-case Wycheproof verification corpus. Production randomized signing also runs on all 30 NIST signing inputs. The suite deliberately excludes internal interfaces, external message representatives, HashML-DSA and other parameter sets that the application does not expose. The executable test is [crypto_vectors_test.go](../internal/guard/crypto_vectors_test.go).

| Mathematical obligation | Executable evidence |
|---|---|
| Correct standardized key expansion | NIST key-generation known answers |
| Correct final pure-signature formatting and deterministic signing | NIST external pure signature-generation known answers |
| Correct accept/reject language | NIST verification answers and Wycheproof cases |
| Context and message separation | Empty/binary messages; 0/255-byte contexts; reject 256-byte contexts; altered message/context |
| Fail-closed expanded-key handling | Public-key hash corruption, out-of-range eta coefficients and corrupted rounding-component tests |
| No stale check followed by an effect | Exhaustive bounded writer/revoker model and an intentionally unsafe negative control |
| No stale recovery completion | Bounded competing-proposal exploration and production recovery-fence tests |
| Transaction/model correspondence | Database concurrency, restart, rollback, revocation and recovery integration tests |
| Evidence binding | Known Merkle root, history mutations, witness rollback/fork checks |

The full host suite also passed with the race detector, including database tests and independent OpenSSL interoperability. A 20-second verifier fuzz run completed 1,612 executions without failure; that is bounded additional evidence, not exhaustive malformed-signature coverage. On the Apple M4 build host, the updated production signer averaged 0.397489 ms/op over 3,080 benchmark iterations, including output self-verification; verification averaged 0.086586 ms/op over 13,916 iterations. These measurements describe that local benchmark, not a production latency guarantee.

The concrete test inventory and measured results are recorded in the accompanying validation logs and [security review](SECURITY_REVIEW.md). Test acceptance is meaningful only when the invalid cases and negative controls actually run; a successful command that skipped the database suite is not evidence of transactional correctness. The rebuilt Linux arm64 and amd64 binaries both passed the full database/vector/model suites and network-disabled CLI/TLS/recovery/witness/restart workflow. AMD64 ran under Docker emulation on the ARM64 host. The optional OpenSSL test skipped in these images and passed separately on the host; the embedded independent vectors did not skip.

### Expanded private-key validation needs precise claims

The library's expanded-key decoder checks length and assumes trusted structured key material. The application adds checks that the stored 64-byte public hash equals SHAKE256 of the supplied public key, every packed eta-4 coefficient is in its permitted range, and the rederived public key agrees. The signing path verifies the resulting signature before releasing it and turns a rejection-loop panic into a signing error. These changes are in the shared [KeyFile.Sign](../internal/guard/protocol.go) path, so CLI, enrollment, checkpoint and witness signing use the same boundary.

These checks are **not complete validation of every redundant expanded-key component**. In particular, the public library API does not expose a comparison of the stored \(t_0\) with its recomputed value. A changed rounding component can sometimes still yield a valid signature; a test must not demand rejection of every such object merely because its bytes changed. The implemented promise is that malformed prechecked components are rejected and a signature that fails verification is not returned. This is a correctness defense, not a general physical-fault defense.

Recent research shows why that last qualification matters. A physical fault experiment attacked a hedged Cortex-M4 implementation, and a 2026 preprint studies rejection-check faults for which individual countermeasures cover different cases. Neither paper establishes a remote vulnerability in this service, and neither supports a blanket claim that randomized signing plus self-verification prevents all faults. ([Jendral, 2024](https://eprint.iacr.org/2024/238); [Meng, 2026 preprint](https://eprint.iacr.org/2026/2567))

### Bounded exploration makes the counterexample reviewable

The writer/revoker model explores a finite interleaving graph. Its protected variant rechecks authority while holding the lock; removing that discipline exposes a stale-authorization trace. Its earlier 13-state protected result applies only to that bounded model, not all SQL executions.

The recovery model fixes two fresh candidate keys A/B, two approvers and one abstract authority invalidation. It explores orderings of A0, A1, B0, B1 and the invalidation, with each attempt used at most once. The state retains the current epoch, each proposal's captured epoch and approver set, completion bits and revoked-key state. Completion must use the current epoch, must not happen twice for one proposal and must not reactivate old keys. `TestRecoveryEpochModel` exhausts **124 guarded reachable states**; its negative control explores 106 states and exposes the shortest counterexample `A0 → epoch change → A1`. It also explicitly checks `A0 → B0 → B1 → A1`, where A's old approval improperly overrides B's completed recovery. See [recovery_test.go](../spec/recovery_test.go).

This abstraction proves a specific finite fence property. It assumes successful signature checks and atomic authority transitions. The production tests connect quarantine, role cycles, key revocation, competing recovery and legacy epoch-zero proposals to that abstract invalidation. The model and those tests are complementary; neither alone proves that the compiler, database or all deployment configurations implement the model.

### Reviewers can run the evidence without a hosted dependency

After extracting the reviewer archive, the complete precompiled path is:

```sh
sha256sum -c SHA256SUMS
./scripts/offline-review.sh --docker
```

Docker must already be present. The archive supplies binaries and PostgreSQL images; the script uses internal networking and a separate `--network none` workflow with image pulling disabled. The source path uses the vendored dependencies and a compatible patched Go toolchain:

```sh
make test
make vet
```

For the focused source-level algorithm/model check, no database is required:

```sh
make crypto
```

The final archive's logs identify the actual vector/model counts. Source commands require the stated Go toolchain; no optional network fetch is part of the checks. See [SUBMISSION.md](SUBMISSION.md) for architecture selection and the full CLI contract.

## Stronger guarantees require explicit protocol changes

### Choose improvements by the security property they add

| Option | Property gained | Decision and implementation cost |
|---|---|---|
| Keep standardized ML-DSA-65 | Established interoperable post-quantum signature construction | Implemented; strengthen tests and composition |
| SHA-384 commitment suite | Stronger collision margin for body/recovery/audit commitments | Implemented v2 with an explicit signed, atomic migration |
| Seed-based private-key storage | Regenerate consistent expanded components from a small trusted seed | Proposed new-key format; preserve explicit legacy import behavior |
| Threshold ML-DSA | Distribute a signing secret so one signing party lacks the complete secret | Research option only; requires a new distributed signing threat model |
| More powerful recovery-root lifecycle | Recover or rotate compromised trust roots with explicit governance | Proposed; ordinary target recovery does not solve this |
| Machine-checked protocol refinement | Stronger correspondence between a model and the implementation | Proposed follow-on; finite exploration is not refinement verification |
| Custom lattice signature | No established benefit for the stated workflow requirement | Reject; adds a new unreviewed primitive and proof burden |
| Quantum circuit or QKD demo | Different physical/network property | No supporting requirement in the supplied overview |

Threshold ML-DSA is a real research direction with implementations producing compatible signatures, not merely an idea to invent here. It introduces distributed randomness, message scheduling, abort and malicious-party obligations. Use it if the required property is that no single signing host holds a complete secret. The existing two-person recovery policy already solves a different problem: separate authorities must approve an identity transition. ([Celi et al., Efficient Threshold ML-DSA](https://eprint.iacr.org/2026/013))

### The implemented v2 upgrade preserves evidence and rejects downgrade

Protocol v2 signs an explicit suite identifier and uses SHA-384 for body, full-public-key, intent, request, recovery, session-token and audit commitments. Contexts identify v2. Random 256-bit challenges and tokens retain their lengths because their guessing/non-reuse purpose differs from collision-resistant content commitments. Existing key IDs stay stable opaque lookup handles; the signed SHA-384 public-key commitment and signature bind the full registered key independently of that legacy handle.

The migration is an administrator-authorized v2 request over a body containing the prior signed v1 checkpoint and the SHA-384 root of the exact same historical prefix. The server checks both roots against the latest prefix under the authority lock. It appends one migration event, advances the protocol and member epochs, invalidates pending challenges/recoveries/sessions, and preserves keys, resources, completed recovery records and operation records in the same transaction. No genesis or historical event is rewritten. An ordinary concurrent write either precedes the migration and makes its prefix stale, or follows it and must use v2. This follows the same row-lock ordering argument as revocation safety.

A matching already committed cutover request returns its retained result; no second cutover occurs. v1 writes and proof reuse are rejected after cutover. A v2 request cannot reuse a subject/operation committed under v1, and offline replay enforces that rule too. Original evidence and witnesses retain their original contexts; a witness can advance from a v1 prefix to v2 but cannot move back.

The database schema guard rejects original executables' authority updates after v2, and the externally configured minimum protocol (default 2) rejects a full v1 backup restore. A separately retained v2 witness anchor additionally checks history continuity. These are compatibility and rollback controls under trusted administration, not defenses against an owner deliberately disabling every control.

The [v2 specification](PROTOCOL_V2.md) gives the exact signing fields, commitment formulas, lifecycle, migration commands and tests. Tests cover unknown suites, mixed contexts, bad prefix commitments, stale/concurrent writes, atomic failure, legacy operation/proof reuse, restored snapshots, older binaries and witness continuity. The stronger checkpoint commits to the observed legacy bytes at cutover; it cannot retroactively strengthen signatures or attestations created before cutover. The remaining root-rotation and seed-storage proposals below are separate, unimplemented work.

### Root rotation needs its own state machine

The current protected recovery identities are bootstrap trust roots. An implementable successor design needs a separate root-set epoch, named root members and a policy specifying which surviving roots may authorize a replacement set. A rotation proposal should bind the entire new root set, the old root epoch, an expiry, proof of possession for every new key and a one-use operation identifier. Completion should invalidate all outstanding approvals under the old root epoch and emit a verifiable root-transition record.

Choosing the quorum is a security/availability decision, not an arbitrary constant. A two-of-two root set prevents one root from replacing the other, but cannot recover from one permanently unavailable root. A larger threshold can tolerate loss while requiring multiple compromises, at the cost of more independent custodians. No online threshold can distinguish two legitimately cooperating roots from those same two fully compromised roots. Recovery from that condition needs an independently defined offline governance or rebootstrap procedure. This design is proposed, not implemented or silently enabled.

### Seed storage and physical hardening have different scopes

A seed-based new-key format can derive all expanded components through the standardized key-generation API and verify the resulting public-key match. Legacy expanded files need an explicit import policy; partial validation must not be mislabeled complete consistency checking. An IETF work-in-progress document recommends seed storage partly for this reason. Its draft status matters: it informs an engineering choice but is not a finalized requirement. ([ML-DSA security considerations draft](https://www.ietf.org/archive/id/draft-connolly-cfrg-ml-dsa-security-considerations-00.html))

Neither format establishes physical protection on an untrusted machine. This work did not perform power/EM analysis, voltage glitching, a compiler-level constant-time proof, reliable memory erasure verification or hardware security module integration. TLS authentication and negotiated transport groups are also separate from application ML-DSA signatures; the presence of TLS alone does not establish a fully post-quantum authenticated channel.

The immediate engineering priority is a defensible chain from requirement to algebra, from algebra to state predicates, and from predicates to independent offline evidence. The remaining open items are explicit: detailed organizer requirements, recovery-root lifecycle, full expanded-key consistency or seed migration, complete rejected-request telemetry, stronger witness distribution and an independent audit. NIST's current potential-updates spreadsheet was located but could not be retrieved during this research; its contents are not claimed to have been checked. The research supports the implemented properties and the migration plan above, not a claim of universal mathematical proof or “best in the world.”
