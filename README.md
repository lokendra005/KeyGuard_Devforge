# Key Identity Guard

An offline protected-resource system for Track 4: real ML-KEM-768 protected reads, ML-DSA-65 identity commands, atomic key rotation/recovery, encrypted client-to-client delivery, verifiable access logs and explainable detection. The judge adapter, CLI, HTTP API and dashboard call the same authority core. No npm install, external API key, hosted service or model is required.

Use **Node 24.11.1**, the organizer’s runtime. State lives outside the source tree. The existing Go/PostgreSQL ledger is preserved separately; its keys, versioned SHA-384 history and deployment are unchanged. Its historical runbook is [LEDGER.md](docs/LEDGER.md).

- [Architecture, algorithms, conditional arguments and limits](docs/TRACK4_DESIGN.md)
- [Operator runbook](docs/TRACK4_OPERATIONS.md)
- [Offline reviewer instructions and evidence](docs/SUBMISSION.md)

## Reviewer entrypoint

`track4_service.cjs` is the sole supported root entrypoint. It reads one JSON request from stdin, writes one JSON response and exits. State persists under `TRACK4_STATE_DIR/keyguard-track4`, falling back to the OS temp directory. `setup`, `read`, `revoke`, `audit` and `protected_read` implement the published contract.

```sh
node --test track4/test/*.test.cjs
python3.12 /path/to/Track-4-Toolkit/validate.py --entry "$PWD/track4_service.cjs"
python3.12 track4/test/interop.py  # requires the judge’s pqcrypto==0.4.0
```

The adapter is a trusted local worker interface, not a network authentication endpoint. HTTP mutations require signed commands. The public validator checks access control, not every cryptographic property or competition score.

## Operate the system

Generate separate identity keys, supply their public keys and your owner/content records in a setup file, then initialize a new private state directory. The operator runbook includes complete schemas and lifecycle commands.

```sh
mkdir -p .local/track4-client
node track4/cli.cjs keygen --out .local/track4-client/operator-key.json
node track4/cli.cjs init --state /private/path/state --input setup.json
node track4/cli.cjs serve --state /private/path/state --port 8444
node track4/cli.cjs dashboard --url http://127.0.0.1:8444 --actor YOUR_OPERATOR --key .local/track4-client/operator-key.json
```

Paste the returned observer token into the dashboard at the service root. It displays real file metadata, current keys, detector evidence and signed access history. Private signing keys never enter the browser.

Loopback development can use HTTP. Other bindings require TLS and an explicit public origin. `Dockerfile.track4` and `compose.track4.yaml` provide a read-only, unprivileged deployment with explicit state/TLS mounts. The reviewer archive includes Linux ARM64/AMD64 Node images: `./scripts/track4-review.sh --docker` loads them locally and tests with networking disabled and a read-only root. It touches no running authority.

## Assurance boundaries

Nodes share one SQLite authority; this is not geographically distributed consensus. Messaging keeps ephemeral receiver keys in memory and intentionally does not implement session resumption. Forward secrecy depends on endpoint integrity and ephemeral-key disposal; JavaScript cannot prove physical memory erasure. Backup rollback detection needs an independently retained checkpoint.

Tests and mathematical arguments are evidence under explicit assumptions, not proof of every program path or a prediction of hidden-test scores. Public-repository eligibility and the required final brief/video remain separate submission obligations.
