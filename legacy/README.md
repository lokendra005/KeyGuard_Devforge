# Optional Go ledger

The default submission at the repository root uses the Node Track 4 implementation. This directory retains the separate Go/PostgreSQL ledger, its vendored dependencies and tests. It is not required to run the judge adapter.

Run `make -C legacy build` with the Go version declared in `go.mod`. The complete ledger runbook is [here](docs/LEDGER.md). Its storage and protocol are separate from Track 4. Moving source files does not migrate or delete any deployed state.

For a deployment whose keys remain at the repository root, export `KIG_LEDGER_STATE_DIR="$PWD/.local"` before `docker compose -f legacy/compose.yaml ...`. Build Linux ledger binaries with `make -C legacy release` first. The retained Compose project name is `keyguard`; the Node deployment uses the distinct `keyguard-track4` project. No running container or database is changed by this source move.
