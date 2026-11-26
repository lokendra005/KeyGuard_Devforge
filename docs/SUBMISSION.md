# Key Identity Guard: offline reviewer runbook

The root `track4_service.cjs` implements the official Track 4 adapter. Start with this service for the competition workflow. The retained Go ledger is a separate optional implementation with its own protocol/history; it is not the adapter backend.

## Verify and run the packaged system

Extract `keyguard-reviewer.tar.gz` into an empty directory, then:

```sh
sha256sum -c SHA256SUMS
./scripts/track4-review.sh --docker
```

The script loads the bundled architecture-specific Node 24.11.1 image, uses `--pull never`, and runs the complete Track 4 suite with networking disabled, read-only root/source, an unprivileged user, dropped capabilities, a memory limit and temporary writable state. Docker must already be available. No live deployment or existing keys are touched. Set `KIG_REVIEW_ARCH=amd64` or `arm64` to select a particular image.

In the organizer runtime, no Docker or dependency installation is needed:

```sh
node --test track4/test/*.test.cjs
python3.12 /path/to/toolkit/validate.py --entry "$PWD/track4_service.cjs"
python3.12 track4/test/interop.py
```

The independent interop test uses the supplied `pqcrypto==0.4.0`. Our runtime uses Node built-ins only. The separate `track4-official-toolkit.tar.gz` is an unmodified export of organizer commit `8901dfbdbfe048853e0bfa25b60583d1e6617a63`; keep it outside your submitted repository. Its validator does not award points or test the protected-read KEM exchange.

To run that unmodified checker against an actual fresh Linux container for every call, load the appropriate packaged image, then use `--entry "$PWD/scripts/track4-container-adapter.cjs"`. That script transports stdin/stdout to the real root adapter; it contains no policy or answers. The independent oracle can use the same transport:

```sh
NODE="$PWD/scripts/track4-container-adapter.cjs" python3.12 track4/test/interop.py
```

## What the tests establish

Read [TRACK4_VALIDATION.md](TRACK4_VALIDATION.md) for exact observed results and limitations. Packaged `validation/track4-*.log` files record the host, Linux architectures, official validator, independent interop, TLS, detection and performance checks. Test identities/keys are generated at runtime; the archive contains no live authority database or operator keys.

The suite checks actual SIGKILL recovery, cutoff boundaries, competing recovery proposals, malformed encodings, read retry after revocation, permission changes, tampered evidence/backups, opaque identifiers including embedded NULs, ciphertext-only relay behavior and real CLI delivery. It deliberately reports failure rather than substituting a mock crypto backend or treating skipped checks as passes.

Open the dashboard with the [operator runbook](TRACK4_OPERATIONS.md). Its actions reach the same core used by the adapter. The [design document](TRACK4_DESIGN.md) specifies state, cryptographic transcripts, mathematical assumptions and unsupported cases. Session resumption is intentionally absent; a lost receiver process must publish a new ephemeral offer.

## Retained Go ledger

The original ledger source, vendored dependencies, six Linux binaries and PostgreSQL images remain in the archive. To repeat that independent suite:

```sh
./scripts/offline-review.sh --docker
```

It needs Docker and uses an isolated database/internal network, followed by a separate network-disabled migration/TLS workflow. Optional OpenSSL checks may skip inside that PostgreSQL image; existing host interop evidence is recorded separately. The v2 SHA-384 migration remains explicit and preserves its own key/history formats. This build does not execute a pending live migration.

## Submission obligations outside automated tests

The organizers require a qualifying public repository and a maximum two-page PDF containing the threat model and accessible five-minute fallback video link. This build does not publish a repository, invent a video link or verify hackathon creation eligibility. Complete those materials separately. Hidden worker tests and official scores are unavailable; passing public and local tests is not organizer acceptance.

Authenticate the archive checksum through an independent trusted channel. Checksums alone detect corruption, not a malicious replacement of both archive and checksum.
