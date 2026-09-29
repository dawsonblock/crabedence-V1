# NEMO runtime transfer provenance

This directory is the full NeMo Relay (NEMO) runtime, vendored into the
Crabedence distribution as `runtimes/nemo-relay/`. It is a copy — not a
submodule, not a subtree. Upstream updates are re-applied deliberately; see
`docs/plan/nemo-runtime-transfer.md` in the Crabedence repository root.

## Source

- Copied from: `NEMO-feat-native-plugin-isolation/` (the NEMO development fork)
- Observed workspace version: `0.9.1-rc.4` (`Cargo.toml`)
- Transfer date: 2026-09-29
- Upstream lineage (from the fork's own `FORK_PROVENANCE.md`): derived from
  [NVIDIA NeMo Relay](https://github.com/NVIDIA/NeMo-Relay). The supplied
  upstream source was an archive, not a Git checkout, with SHA-256
  `8b84004ecfb5d214db2a827d8d7828bc070ff2b28e8211de74e7ce4de7fce53f` and
  observed workspace version `0.9.0`. Fork lineage:
  `0.9.0 → 0.9.1-rc.1 → 0.9.1-rc.2 → 0.9.1-rc.3 → 0.9.1-rc.4`.

## Exclusions

Build artifacts and local state were not vendored: `target/` (2.0 GB),
`.git/`, `node_modules/`, `.venv/`, `.uv-cache/`, `dist/`, `__pycache__/`,
`*.pyc`, `.pytest_cache/`, `.ruff_cache/`, `.mypy_cache/`, `.DS_Store`.

## Vendored tree fingerprints

Two digests, two meanings. Do not confuse them.

### What upstream we copied

1438 files. Digest over the sorted `sha256(path, content)` records of the
source tree as it was copied, before any local modification:

```text
050a9cae3f9eeb4f4f0f34f89ccafd7617d93b4c7e051fe08f3a1d7d0c5e59fa
```

Recompute against the source tree (from its root):

```sh
find . -type f -not -path './target/*' -print0 \
  | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256
```

### What this distribution ships

The vendored tree as it stands here — upstream plus the local modifications
listed below. This is the identity a release binds, produced by
`cmd/nemo-runtime-digest`, which the release evidence generator runs so an
artifact carries the runtime it ships rather than only the repository it came
from:

```sh
go run ./cmd/nemo-runtime-digest -envelope
```

The tool's digest is the same definition as the shell command above, verified
to agree byte-for-byte, so either can be used to check the other. Current
value: `c54315a76a804e8062d52bd3e785ea56d228a6377139034b2401d3f89447bc3e`
(1455 files, runtime version `0.9.1-rc.4`).

## Local modifications

A recursive diff between the source copy and this directory reports these
differing files — every other file is byte-identical:

| File | Difference |
| --- | --- |
| `Cargo.toml` | two added workspace members: `bridges/nemo-crabedence` and `bridges/nemo-effect-router` |
| `Cargo.lock` | the two crate entries and their dependency edges |
| `crates/cli/src/mcp_environment.rs` | security patch: the MCP environment allowlist no longer forwards credential material (see below) |
| `integrations/coding-agents/codex/.mcp.json` | regenerated to match the patched allowlist; a checked-in test asserts the two agree |

### Security patch: MCP environment credentials

`crates/cli/src/mcp_environment.rs` forwarded the operator's cloud credentials
into MCP subprocesses. The `AWS_` prefix was allowlisted for region and
endpoint configuration, and `BASE_MCP_ENV_VARS` listed the credential names
explicitly, so a plugin subprocess inherited `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, the shared credentials and config
files, the web-identity token file, and the container credential endpoints.

The patch removes those names from the allowlist, adds them — plus the
Crabedence, GitHub, and OpenComputer credential names — to
`BLOCKED_MCP_ENV_VARS`, and makes the blocklist authoritative over the base
allowlist so a name in both can never be forwarded. Region and endpoint
configuration still flows: this is a credential boundary, not an AWS ban.

`scripts/check-nemo-credential-isolation.sh` asserts both halves — the plugin
path is silent and the blocklist covers every credential name — and unit tests
in the module pin the behavior. Residual, stated in the module: `HOME` is
forwarded, so a subprocess can still read `~/.aws/credentials` if the operator
has one there; closing that is a deployment property, not something the list
can do.

Plus additions that are not upstream files:

- `bridges/nemo-crabedence/` — the Crabedence ABI bridge: transport, the
  strict ABI scanner, envelope verification, outcome mapping, and the
  execution port;
- `bridges/nemo-effect-router/` — the effect router: resolves the execution
  path from the verified registry and holds the effect-isolation invariant;
- this file.

Both crates are authored in the Crabedence repository and licensed Apache-2.0
under the workspace license.

Re-applying those edits after an upstream refresh is the documented update
procedure (see `docs/plan/nemo-runtime-transfer.md` in the Crabedence
repository root).
