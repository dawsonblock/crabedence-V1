<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Milestone: Linux restricted native plugin host

**Status** (this document records what is enforced; where a claim rests on a
probe rather than a test name, it says so):

- **The policy exists and is explicit.** `NativeIsolationPolicy` gains
  `restricted-linux`, spelled that way in `NEMO_RELAY_NATIVE_ISOLATION`. A level
  this build cannot deliver is refused at startup, before anything is created,
  rather than served with a host that runs without the confinement the
  configuration states.
- **The host confines itself before a plugin byte exists.** The mechanism is
  `crates/native-loader/src/bin/unix/linux_sandbox.rs`, entered from the host's
  entrypoint on Linux: user, mount, network, IPC, UTS and PID namespaces, a
  Landlock filesystem allow-list, a seccomp filter, and a dropped capability
  bounding set, in that order. There is no bundle and no signing requirement —
  the confinement is a property of what the process does at startup, which is
  why the supervisor may exec a staged private copy: staging closes the window
  between digesting a path and executing it, and on Linux costs the copy and
  nothing else.
- **The kernel channel arrives already connected.** `connect`, `sendmsg` and
  `sendmmsg` are dead inside the boundary, and `sendto` answers `EPERM` the
  moment it carries a destination address — Landlock does not mediate
  filesystem unix-socket connects on every kernel, so reach is removed at the
  syscall rather than assumed from the filesystem rule. The supervisor
  therefore connects to the kernel's callback listener *before* spawning the
  host, clears `FD_CLOEXEC` in the child, and hands the descriptor over in
  `NEMO_RELAY_KERNEL_FD`. The host builds its gRPC client on that descriptor
  and never connects again. `NEMO_RELAY_KERNEL_SOCKET` and
  `NEMO_RELAY_KERNEL_FD` are mutually exclusive; a build that offers both is
  refused.
- **Approved artifacts arrive over the session.** The confined host cannot read
  the artifact's source path — that is the point — so the artifact crosses as
  bytes on the authenticated session (`StagedArtifactTransfer`), is re-verified
  after the host writes it, and only the promoted copy inside the session
  directory is ever loaded. The host's `HOME` is a directory inside its own
  session root, so the staging tree and the scratch the runtime expects are
  inside the one place the allow-list makes writable.
- **The probe is the requirement.** `unmet_requirements` does not read a sysctl
  and infer; it runs this binary with `NEMO_RELAY_PLUGIN_HOST_PROBE=confinement`
  and requires `NEMO_RELAY_PROBE_CONFINED` on stdout. The confined child acks
  only after proving the denials in `self_check`: a system file is unreadable,
  a write outside the session directory fails, a TCP connect fails, spawning
  `/bin/true` fails, and `connect` to a unix socket fails *both* outside the
  allow-list and inside it — the second direction is what separates "the
  filesystem said no" from "the call itself is dead". A missing listener, a
  missing ack, or any check that succeeded fails the probe, and the probe's
  stderr is reported rather than swallowed.

## Selecting the policy

```sh
export NEMO_RELAY_NATIVE_ISOLATION=restricted-linux
```

Unknown values fail activation; they do not fall back to the trusted policy.
On non-Linux the requirement is `the platform is not Linux`. On Linux where the
probe cannot run the confined child, the refusal names the mechanism — the
kernel may deny unprivileged user namespaces outright
(`kernel.unprivileged_userns_clone`) or mediate them per binary through
AppArmor (`kernel.apparmor_restrict_unprivileged_userns`, Ubuntu 23.10+),
which needs a profile granting `nemo-plugin-host` the userns permission.

## The boundary

```text
      Python / Node / CLI / FFI
                │
                ▼
            Relay kernel
                │  authenticated session (the existing protocol)
                ▼
┌──────────────────────────────────────────────────┐
│ nemo-plugin-host (staged private copy is fine)   │
│   userns · mount · net · ipc · uts · pid ns      │
│   Landlock allow-list · seccomp deny-list        │
│   PR_SET_NO_NEW_PRIVS · PR_SET_DUMPABLE=0        │
│   capabilities dropped · rlimits from supervisor │
│                                                  │
│   kernel channel: inherited connected descriptor │
│        │                                         │
│        ▼                                         │
│   approved plugin, staged inside the session dir │
└──────────────────────────────────────────────────┘
```

## The confinement, mechanism by mechanism

- **User namespace first.** `unshare(CLONE_NEWUSER)` is what lets an
  unprivileged process take the rest; uid/gid map the confined root to the
  real account (`0 <uid> 1`) with `setgroups` denied first. Its failure is the
  refusal a deployer sees when the kernel forbids unprivileged userns.
- **Mount namespace** with `MS_PRIVATE` propagation everywhere, so nothing
  mounted inside appears outside and nothing outside propagates in.
- **Network namespace with no interfaces.** A plugin cannot open a connection
  because there is nothing to open one over; abstract unix sockets die with it.
- **IPC and UTS namespaces** keep SysV/POSIX objects and the hostname to the
  sandbox.
- **PID namespace, entered through a fork.** `CLONE_NEWPID` confines only
  children, so the serving process is the inner fork — pid 1 of its namespace —
  while the outer process becomes a wait shim that mirrors the inner one's
  exit status. That keeps the supervisor's view honest: `kill_on_drop` and the
  startup deadline act on the outer pid, and `PR_SET_PDEATHSIG` propagates its
  death inward.
- **A confined `/proc`, best effort with a fail-closed fallback.** The new PID
  namespace gets a fresh procfs mounted `nosuid,noexec,nodev` where the kernel
  allows it. Where it refuses — nested user namespaces in unprivileged
  containers cannot create procfs superblocks, and the inherited `/proc` mount
  is locked to the ancestor user namespace — the mountpoint still names the
  host's table, so `/proc` is withheld from the Landlock allow-list entirely:
  the host loses procfs rather than leaking the host's process table, and the
  refusal is logged.
- **Landlock, deny by default** for every handled right the kernel's ABI
  offers (v1 through v5's `IOCTL_DEV`). The allow-list is the filesystem the
  host needs to be a host: the session directory read/write, `/usr`, `/lib`,
  `/lib64`, `/bin`, `/sbin` read/execute, the loader configuration
  (`ld.so.conf`, `ld.so.cache`, `ld.so.conf.d`, `passwd`, `group`,
  `nsswitch.conf`) read, `/dev/null` and `/dev/full` read/write, `/dev/zero`,
  `/dev/urandom`, `/dev/random` read, and `/proc` read only when the confined
  procfs mounted. Nothing under an account's home is listed. Kernels before
  5.13 or built without the Landlock LSM refuse the ruleset — and the policy.
- **Seccomp, architecture-checked.** The filter verifies `seccomp_data.arch`
  against the build's architecture (`AUDIT_ARCH_X86_64`,
  `AUDIT_ARCH_AARCH64`) and kills a mismatch, kills the x32 ABI bit outright on
  x86_64, then denies with `EPERM` — a probe gets an error it can log, not a
  crash the supervisor has to explain — the calls that would dismantle or
  escape the confinement: `execve`/`execveat`, `ptrace`, `process_vm_*`, the
  mount family (`mount`, `umount2`, `pivot_root`, `move_mount`, `fsopen`,
  `fsconfig`, `fsmount`, `fspick`, `open_tree`, `mount_setattr`), `setns`,
  `unshare`, `chroot`, `kexec*`, module loading, `bpf`, `perf_event_open`,
  `keyctl`, `io_uring`, `userfaultfd`, quota/acct/syslog/reboot/handle
  interfaces, hostname mutation, `kcmp` — and the reach blockers:
  `connect`, `sendmsg`, `sendmmsg` unconditionally, `sendto` when its
  destination argument is non-NULL (a NULL destination on a connected socket is
  how ordinary writes carry `MSG_NOSIGNAL`, which the serving loop needs; a
  named destination is the reach being denied). x86_64 and aarch64 are the
  supported targets; other architectures do not compile this path.
- **Capabilities and limits.** `PR_SET_NO_NEW_PRIVS` precedes Landlock and
  seccomp as required; `PR_SET_DUMPABLE` is cleared so neither `ptrace` nor a
  `/proc` view elsewhere could read the process's memory; the capability
  bounding set is dropped. File-descriptor, address-space and process-count
  ceilings come from the supervisor's `pre_exec` limits, same as a trusted
  host.

## What this boundary is not

This is namespace confinement plus syscall filtering — not a VM boundary. The
residual risk is the Linux syscall surface itself: a kernel exploit in an
allowed call is inside the threat model's remaining surface, which is why the
deny-list narrows it rather than pretending to eliminate it. `trusted-process`
remains what it always was — crash containment, bounded execution, resource
ceilings — and is not a security boundary for untrusted code. For code assumed
adversarial, the boundary to reach is a VM; this level is the one below it.

```text
TRUSTED      ordinary child process
             crash containment, bounded execution, resource ceilings
RESTRICTED   namespace + Landlock + seccomp child
             the above, plus filesystem, network and process-table confinement
HOSTILE      a VM boundary                 (not implemented; a different mechanism)
```

## What is enforced now, and by what

| claim | enforced by |
|---|---|
| A restricted policy this kernel cannot deliver is refused before the host starts | `a_restricted_linux_policy_refuses_a_host_that_cannot_probe` |
| A confined host completes transfer, digest verification, load and registration | `a_restricted_linux_host_loads_only_the_transferred_approved_copy` |
| The sandbox's denials hold in the confined child itself | the probe's `self_check`, exercised by both tests above through `unmet_requirements`: every entry in `BLOCKED_SYSCALLS` must answer `EPERM`, reads and writes outside the Landlock allow-list must refuse (including `/etc/shadow`, `/root`, `/home` and writes to the read-only system tree), a mounted `/proc` may show only the confined init, a `sendto` carrying a destination must refuse, and the `dumpable`/`no_new_privs`/capability-bounding state must still be set |
| An artifact that declares confinement cannot be hosted unconfined | `security.requires_confinement` in `relay-plugin.toml`, enforced by the runtime composition before a host starts |
| An ambient `NEMO_RELAY_PLUGIN_HOST` path cannot stand in for a pinned host | the composition refuses an override whose bytes nothing binds unless `NEMO_RELAY_PLUGIN_HOST_ALLOW_UNPINNED=1` acknowledges it as development |
| The policy spelling, defaults and refusal to fall back | the `isolation_policy` unit tests |

Both process tests run in the plugin-host suite; on a host where unprivileged
user namespaces are unavailable the load test reports the unmet requirement and
skips, while the refusal test still asserts that the policy fails closed there.
A lane that sets `NEMO_RELAY_REQUIRE_RESTRICTED_LINUX` — the linux-amd64 CI
lane is that designation — turns the unmet requirement into a failure instead,
so the positive confinement claim cannot be qualified by a skip.
