# Independent ML-DSA-65 test fixtures

`crypto-vectors.json.gz` contains public test keys and signatures, never operator keys.
It is embedded into the standalone test binary, so reviewers need no downloads or
working-directory-specific data files. No network is used by these tests.

Sources pinned for this import:

- NIST ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`,
  `gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/{prompt,expectedResults}.json`.
- C2SP Wycheproof commit `65ca494727a52944c204441c860b039e6786b99b`,
  `testvectors_v1/mldsa_65_verify_test.json`, Apache 2.0 (license alongside this file).

The fixture's `sources` array records all seven exact upstream URLs and original
file SHA-256 checksums. `scripts/import-crypto-vectors.py` reproduces extraction
and deterministic gzip compression from those downloaded files. It performs no
network access and asserts case counts to prevent an unnoticed corpus change.

Coverage: 25 NIST key-generation known answers, 15 byte-exact deterministic
signature-generation known answers, verification of all 30 supplied NIST
signature-generation outputs, and 225 independent verification cases (15 NIST
plus the entire 210-case Wycheproof corpus; 82 accepted, 143 rejected).
Production randomized signing is exercised on all 30 NIST signing keys/messages.
Randomized signatures are not compared byte-for-byte, because our production API
intentionally obtains its own randomness.

Only external, pure ML-DSA-65 is exposed by this application. HashML-DSA,
caller-supplied external mu, internal signing, ML-DSA-44 and ML-DSA-87 groups are
deliberately excluded. We do not expose unsafe library internals just to claim
more test coverage. Running public ACVP examples is not ACVP/CAVP validation or
FIPS certification. Cases include canonical hint encoding, signature/public-key
lengths, invalid contexts, modified signatures and valid boundary cases.
