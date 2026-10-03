<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Native plugin isolation — current enforcement

This document is the current account of what the tree enforces. Every figure in
it is measured by a gate rather than maintained by hand; the milestone journal
that produced the boundary — including every interim number it recorded on the
way — lives in [PLUGIN-ISOLATION-HISTORY.md](PLUGIN-ISOLATION-HISTORY.md) and
is history, not drift. Where the two disagree, this document is right.

**Current status, as the tests enforce it:**

- **Registration coverage: 16 of 16.** Pinned by
  `the_boundary_serves_a_named_subset_of_the_registration_surface` in
  `crates/plugin-host/tests/architecture.rs`, whose unserved half is now empty. The last
  two to cross were the LLM sanitizers — one codec capability protocol, one bridge that
  turns a plugin's synchronous codec call into the kernel's asynchronous one, and a real
  child in each direction resolving the call's codec through the kernel. Every attachment
  point the ABI exposes is served, and the match that installs proxies is exhaustive: a
  class added to the ABI fails to compile there rather than being refused at runtime.
- **Kernel-process unsafe tokens: 27**, measured by `just tcb-report` — down from
  648 when the loader, the SDK and the ABI left the kernel's process. The one it
  gained is the `pre_exec` block that clears `FD_CLOEXEC` on the kernel channel
  a restricted-linux child inherits, which is the call that has to run between
  fork and exec. The loader's tokens are budgeted on the host side now, at 325 —
  the restricted-linux confinement is written against the syscall surface, so its
  unsafe count is the boundary itself — and the two numbers are recorded rather
  than one being inferred from the other.
- **No root reaches the loader at all, on any platform the packages ship on.**
  `just tcb-report` checks the property rather than the progress, for the kernel
  library and for the composition surfaces together: on each of the five targets the
  plugin-hosting packages are built for, the closure of
  `{nemo-relay, nemo-relay-cli, nemo-relay-ffi, nemo-relay-python, nemo-relay-node}`
  intersects
  `{libloading, nemo-relay-native-loader, nemo-relay-native-abi, nemo-relay-plugin}`
  in **nothing**, and any reach is a failure. The child's own end is the loader
  crate's now, so the supervisor's crate does not link it and a binary that runs the
  kernel cannot open a library. The one platform deliberately not among the five is
  Windows: the Node binding's N-API machinery resolves a `libloading` of its own
  there, native-plugin isolation is not implemented on that platform, and the policy
  records the target instead of dropping it — the record is measured like the rest,
  so a target whose resolve stops reaching the loader fails the gate rather than
  leaving an exemption that quietly stopped being true.
- **A boundary change re-runs every lane that carries an artifact.** The paths that
  can change what the process boundary does — the loader, the host, the ABI, the wire
  and contract crates between them, and the scripts that bundle a host into a package
  or check one after installation — are one group in `.github/ci-path-filters.yml`,
  and `ci_changes.yml` composes the Rust, CLI, Go, Python and Node lanes from it.
  `scripts/qualification/matrix.py` refuses a tree where the group loses a crate or a
  lane stops reacting, so this is a gate rather than a convention. It closes a
  qualification hole: the loader and the host are covered by source tests either way,
  and the installed Python and Node lanes were exactly the ones a change to either
  could leave skipped.
- **Installed-artifact qualification is end-to-end on Linux amd64.** The Python wheel
  lane and the Node `InstalledArtifact` job each build a real fixture from source,
  install the package the build produced, and require a plugin to run in the host that
  package installed, with nothing naming a host in the environment. The other
  packaged targets — Linux arm64, the musllinux wheels, macOS arm64 and the Windows
  packages — get package install, import and host-startup smoke coverage plus the
  source-level isolation tests. That is not the same claim, and it is recorded as a
  row of its own in the matrix rather than folded into the two above.
- **Native ABI version: 5** (`NEMO_RELAY_NATIVE_ABI_VERSION` in `crates/native-abi`,
  re-exported by `crates/plugin` so every author-facing path is unchanged).
- **Plugin compatibility:** the CLI, FFI, Python and Node serve plugins from
  another process. No consumer reaches the in-process activation path any more,
  and that is pinned by the architecture test (`INDIRECT_LOAD_CALLERS` in
  `crates/plugin-host/tests/architecture.rs`) rather than recorded only here: the
  list is empty, and it stays in the test so the next consumer to reach for that
  route fails the check instead of being grandfathered by a missing one. The loader
  is not linked into the kernel any more, which is why the unsafe count below is a
  twenty-fourth of what it was.
- **Windows native plugin hosting is explicitly unsupported.** Shared activation,
  policy and error APIs compile on Windows; the socket transport and process
  supervisor compile only on Unix. Selecting a native plugin on Windows returns
  `PluginHostError::UnsupportedPlatform`. The Windows CI lane checks every
  workspace target and compiles every test without running native-plugin tests.
- **Claims: 44 enforced, 1 asserted and not yet.** Every claim this document makes
  is listed with what enforces it in `security/QUALIFICATION-MATRIX.md`, generated
  from `security/qualification-matrix.toml`, and `just qualification-matrix`
  resolves each name against the tree. A test that is renamed or deleted turns that
  gate red, so a sentence here cannot go on describing something nothing checks.
- **The hostile class is a named refusal, not a hidden level.** The deployment
  spellings `hostile`, `hostile-vm` and `vm` are recognised at parse time and
  refused with the boundary they asked for — a VM-grade backend this build does
  not provide — rather than rejected as unknown values or silently mapped onto
  the restricted levels. Every level the runtime does serve reports its trust
  model as data, and no level claims to separate a plugin from the host process
  that loaded it: the restricted levels confine the process's reach on the
  machine, which is a different statement than protecting the process from the
  code inside it. `nemo-relay doctor` reports the selected policy and its class,
  and a hostile-class request fails the check rather than showing a selection
  the runtime would never honor.
  A claim enforced by a recipe also names the workflow that invokes it, so deleting
  the CI step turns the row red instead of leaving a recipe that nothing runs. The
  claim that is asserted rather than enforced is named there, with why.

What is left of the kernel's `unsafe` is nothing to do with loading. The loader's
325 occurrences — the ABI adapter's signatures and witnesses, plus the
restricted-linux confinement's syscall surface — and the SDK's 220 and
the ABI's 113 all live outside the kernel's process now, and `security/tcb.toml`
records each of them where they are rather than restating them here, which is what a
paragraph cannot be trusted to do. `just tcb-report` prints the figure this milestone
is judged on, and the gate requires the figure to appear exactly once in this
document:

```
kernel-process unsafe tokens: 27
```

## The boundary

```text
                      NEMO Runtime
                           |
                 PluginExecutionClient
                           |
                    process / RPC
                           |
          +----------------+----------------+
          |                                 |
    kernel process                  plugin-host process
                                            |
                                            +- native loader
                                            +- dlopen / libloading
                                            +- FFI and plugin ABI
                                            +- unsafe
```

The kernel owns the interface. The runtime supplies the implementation. Dynamic
loading happens on the far side, so the trusted side never loads a library.

## What this build does not provide

- **No hostile-code boundary.** `hostile`, `hostile-vm` and `vm` are named
  refusals at parse time. Running arbitrary third-party native code still needs
  a microVM, VM, or comparably constrained backend this build does not carry.
- **No in-process plugin loading anywhere in a shipped consumer.** The
  compatibility backend is development-only and unreachable from the CLI, FFI,
  Python or Node surfaces.
- **No Windows native plugin hosting** — `PluginHostError::UnsupportedPlatform`.
- **macOS is not equivalent to Linux confinement.** The restricted host on macOS
  applies seatbelt policy and resource ceilings; it is documented separately in
  `security/MACOS-RESTRICTED-HOST.md` and is not a claim of isolation from
  malicious code inside the plugin-host process. Hard resource ceilings are
  stronger on Linux, where namespaces, Landlock, seccomp, capability dropping
  and `no_new_privs` compose.

The per-claim enforcement map is `security/QUALIFICATION-MATRIX.md`; the unsafe
budget is `security/tcb.toml`; the chronicle of how the boundary got here is
[PLUGIN-ISOLATION-HISTORY.md](PLUGIN-ISOLATION-HISTORY.md).
