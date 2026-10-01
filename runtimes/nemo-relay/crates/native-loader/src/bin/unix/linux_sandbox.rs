// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The confinement a `restricted-linux` host applies to itself.
//!
//! The boundary is built from kernel primitives the host enters before a single
//! plugin byte exists in the process:
//!
//! - a user namespace, so the other namespaces may be created unprivileged and
//!   the confined uid no longer names a real account;
//! - mount, network, IPC, UTS and PID namespaces — the network namespace has no
//!   interfaces, so a plugin cannot open a connection, and the PID namespace is
//!   entered through a fork so the serving process becomes its init;
//! - a Landlock filesystem allow-list covering the libraries the loader needs,
//!   the session directory the supervisor handed over, and nothing else;
//! - a seccomp filter that takes back the syscalls the namespaces granted the
//!   process inside its own namespace — mount, unshare, setns, execve, ptrace
//!   and the rest of the escape surface — and the ones that would reopen
//!   reachability: `connect` and the addressed datagram sends are dead, so no
//!   socket path outside the allow-list can be spoken to either.
//!
//! What remains reachable inside the box is exactly the contract the host
//! serves: the session directory, the approved artifacts staged beneath it,
//! the kernel callback channel — a descriptor the supervisor connected and
//! handed over before this boundary existed, since `connect` is dead inside —
//! and the plugin's own memory.
//!
//! The check this module gives the deployment is honest: the policy layer spawns
//! this binary with [`PROBE_ENV`] set, and the answer is whether the confined
//! child actually ran the denials in [`self_check`] and they held — not whether
//! a sysctl file suggested they would.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The probe contract is defined beside the policy that checks it.
pub(crate) use nemo_relay_plugin_host::isolation_policy::{
    CONFINEMENT_PROBE_ACK as PROBE_ACK, CONFINEMENT_PROBE_ENV as PROBE_ENV,
    CONFINEMENT_PROBE_VALUE as PROBE_VALUE,
};

// The seccomp filter encodes architecture-specific syscall numbers; the confinement
// is implemented for the two release targets.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("restricted-linux supports x86_64 and aarch64");

/// Everything under a syscall number that a confined host must never perform.
///
/// These are not the syscalls the serving loop uses — the gRPC transport needs
/// file operations, epoll, futex and its socket — they are the ones that would
/// dismantle the confinement or reach outside it. Denied with `EPERM` rather
/// than by killing the process: a plugin probing the boundary gets an error it
/// can log, not a crash the supervisor has to explain.
const BLOCKED_SYSCALLS: &[u32] = &[
    libc::SYS_execve as u32,
    libc::SYS_execveat as u32,
    libc::SYS_ptrace as u32,
    libc::SYS_process_vm_readv as u32,
    libc::SYS_process_vm_writev as u32,
    // The confined host connects to nothing: its kernel callback channel is a
    // descriptor the supervisor connected and handed over before the boundary
    // existed. Denying connect and every datagram-with-address send form is
    // what closes the reach Landlock does not mediate — filesystem unix
    // sockets the allow-list does not name stay unreachable, and so does
    // anything else a socket call could have reached. `sendto` is not in this
    // list because it is also how a plain socket write carries MSG_NOSIGNAL —
    // it is denied by address below instead: NULL destination is a connected
    // write, a named one is the reach being denied.
    libc::SYS_connect as u32,
    libc::SYS_sendmsg as u32,
    libc::SYS_sendmmsg as u32,
    libc::SYS_mount as u32,
    libc::SYS_umount2 as u32,
    libc::SYS_pivot_root as u32,
    libc::SYS_move_mount as u32,
    libc::SYS_fsopen as u32,
    libc::SYS_fsconfig as u32,
    libc::SYS_fsmount as u32,
    libc::SYS_fspick as u32,
    libc::SYS_open_tree as u32,
    libc::SYS_mount_setattr as u32,
    libc::SYS_setns as u32,
    libc::SYS_unshare as u32,
    libc::SYS_chroot as u32,
    libc::SYS_kexec_load as u32,
    libc::SYS_kexec_file_load as u32,
    libc::SYS_init_module as u32,
    libc::SYS_finit_module as u32,
    libc::SYS_delete_module as u32,
    libc::SYS_bpf as u32,
    libc::SYS_perf_event_open as u32,
    libc::SYS_keyctl as u32,
    libc::SYS_add_key as u32,
    libc::SYS_request_key as u32,
    libc::SYS_name_to_handle_at as u32,
    libc::SYS_open_by_handle_at as u32,
    libc::SYS_swapon as u32,
    libc::SYS_swapoff as u32,
    libc::SYS_reboot as u32,
    libc::SYS_userfaultfd as u32,
    libc::SYS_io_uring_setup as u32,
    libc::SYS_io_uring_enter as u32,
    libc::SYS_io_uring_register as u32,
    libc::SYS_acct as u32,
    libc::SYS_quotactl as u32,
    libc::SYS_quotactl_fd as u32,
    libc::SYS_sethostname as u32,
    libc::SYS_setdomainname as u32,
    libc::SYS_syslog as u32,
    libc::SYS_kcmp as u32,
];

/// Enter the confined sandbox and return only in the confined child.
///
/// `allowed_root` is the one place on the filesystem the confined process may
/// write: the session directory that holds this host's sockets and its staged
/// artifacts. The supervisor child is the process that returns; the outer
/// process becomes a wait shim that mirrors the inner one's exit, which is what
/// lets the PID namespace hold a process the supervisor started. `cleanup` is a
/// path only the shim can still reach — the probe's outside-socket directory —
/// removed after the confined child exits.
///
/// Failure here means the confinement the deployment named cannot be delivered,
/// and a host that cannot confine does not start.
pub(crate) fn enter(allowed_root: &Path, cleanup: Option<&Path>) -> Result<(), String> {
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    // The user namespace comes first: it is what lets an unprivileged process
    // take the mount, network, IPC, UTS and PID namespaces without a setuid
    // helper. An EPERM here is a host that has disabled unprivileged user
    // namespaces outright or mediates them through AppArmor — the message names
    // the knobs so a deployer can tell "unsupported" from "restricted".
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(format!(
            "unshare(CLONE_NEWUSER) failed: {}; unprivileged user namespaces are unavailable to \
             this binary — the kernel may disable them (kernel.unprivileged_userns_clone) or \
             mediate them per-binary through AppArmor \
             (kernel.apparmor_restrict_unprivileged_userns), which needs a profile granting this \
             host the userns permission",
            std::io::Error::last_os_error()
        ));
    }
    write_proc("setgroups", "deny")?;
    write_proc("uid_map", &format!("0 {real_uid} 1"))?;
    write_proc("gid_map", &format!("0 {real_gid} 1"))?;

    let remaining = libc::CLONE_NEWNS
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWPID;
    if unsafe { libc::unshare(remaining) } != 0 {
        return Err(format!(
            "unshare(mount|net|ipc|uts|pid namespaces) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Propagation off: a mount event elsewhere must not appear inside this
    // namespace, and nothing done here may appear outside it.
    if unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(format!(
            "could not make mounts private: {}",
            std::io::Error::last_os_error()
        ));
    }

    // CLONE_NEWPID confines only children of the process that creates it, so the
    // serving process has to be a child of the one that unshared. The forked
    // inner process is pid 1 of the new namespace; the outer process waits and
    // mirrors its exit, which is also what keeps the supervisor's view honest —
    // kill_on_drop and the startup deadline act on the outer pid while
    // PDEATHSIG propagates any death of it to the confined child.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "could not enter the PID namespace: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid > 0 {
        wait_shim(pid, cleanup);
    }

    // Confined child from here: pid 1 of the new PID namespace.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return Err(format!(
                "could not bind this host's death to its supervisor's: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Nobody may ptrace this process or read its memory through /proc even
        // where the credentials would allow it.
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // No new privileges ever: required by Landlock and seccomp, and wanted
        // in its own right.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "could not seal privileges: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    // A fresh /proc for the new PID namespace: the process table a plugin sees
    // is the table of this sandbox, not the host's. Where the kernel refuses
    // the mount — nested user namespaces in unprivileged containers cannot
    // create procfs superblocks, and the inherited /proc mount is locked to
    // the ancestor user namespace — the host's /proc is still sitting on that
    // mountpoint. The boundary cannot hide it, so the allow-list below
    // withholds /proc entirely: the confined host loses procfs rather than
    // leaking the host's process table.
    let have_proc = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            std::ptr::null(),
        )
    } == 0;
    if !have_proc {
        eprintln!(
            "restricted-linux: the kernel refused a confined /proc; plugins get no procfs view"
        );
    }
    landlock_restrict(allowed_root, have_proc)?;
    install_seccomp()?;
    drop_capabilities();
    Ok(())
}

/// Run the confinement probe: enter the sandbox, prove the denials, ack.
///
/// Exits 0 only when the confined child confirmed the boundary held; the caller
/// still has to see [`PROBE_ACK`] on stdout, because a binary that ignored this
/// protocol also exits 0.
pub(crate) fn probe() -> ExitCode {
    let root = std::env::var_os("NEMO_RELAY_PLUGIN_HOST_SOCKET")
        .map(PathBuf::from)
        .and_then(|socket| socket.parent().map(Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir);
    // The allow-list grants what exists; a root the probe invents has to be
    // created before the sandbox makes creating anything else impossible.
    let _ = std::fs::create_dir_all(&root);
    // Two listeners are bound before the boundary exists: one inside the
    // session root, one outside it. The confined half then proves `connect`
    // is dead in both directions — a filesystem socket can carry a call
    // outside the allow-list without tripping a fs-mediated check, and the
    // only answer that is honest is the call itself being gone.
    let inside_path = root.join(format!("probe-inside-{}.sock", std::process::id()));
    let inside = std::os::unix::net::UnixListener::bind(&inside_path).ok();
    let outside_dir =
        std::env::temp_dir().join(format!("nemo-probe-outside-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&outside_dir);
    let outside_path = outside_dir.join("probe-outside.sock");
    let outside = std::os::unix::net::UnixListener::bind(&outside_path).ok();
    let inside_path = inside.is_some().then_some(inside_path);
    let outside_probe = outside.is_some().then_some(outside_path);
    // The listeners must outlive the checks: a socket whose listener closed
    // refuses connections for the wrong reason, which would read as a denial
    // the boundary never delivered. The wait shim owns the outside directory
    // afterwards — it is the process that can still reach it.
    enter(&root, Some(&outside_dir))
        .map(|()| self_check(&root, inside_path, outside_probe))
        .unwrap_or_else(|error| {
            eprintln!("{error}");
            ExitCode::from(1)
        })
}

/// The denials the confined probe proves before it acks.
///
/// Each check is a real operation against the boundary rather than a flag: a
/// confinement that announced itself without holding would pass a probe that
/// only asked whether the calls returned.
fn self_check(
    allowed_root: &Path,
    inside_socket: Option<PathBuf>,
    outside_socket: Option<PathBuf>,
) -> ExitCode {
    let mut failures = Vec::new();
    denied(
        &mut failures,
        "reading a system file",
        std::fs::read_to_string("/etc/hostname").map(|_| ()),
    );
    denied(
        &mut failures,
        "writing outside the session directory",
        std::fs::write("/etc/nemo-probe-write", b"x"),
    );
    denied(
        &mut failures,
        "opening a network connection",
        std::net::TcpStream::connect("192.0.2.1:9").map(|_| ()),
    );
    denied(
        &mut failures,
        "spawning a process",
        std::process::Command::new("/bin/true").status().map(|_| ()),
    );
    // The confined process cannot connect anywhere: the kernel callback
    // channel arrives as a descriptor the supervisor connected beforehand, so
    // `connect` answers EPERM outright — to a socket outside the allow-list
    // and to one inside it alike. Both directions are checked because "the
    // filesystem said no" and "the call itself is dead" are different
    // boundaries, and only the second is true here.
    match outside_socket {
        Some(path) => denied(
            &mut failures,
            "connecting to a socket outside the session directory",
            std::os::unix::net::UnixStream::connect(&path).map(|_| ()),
        ),
        None => failures
            .push("the probe could not verify socket confinement: no outside listener".to_string()),
    }
    match &inside_socket {
        Some(path) => denied(
            &mut failures,
            "connecting even to a socket inside the session directory",
            std::os::unix::net::UnixStream::connect(path).map(|_| ()),
        ),
        None => failures.push(
            "the probe could not verify connect is unavailable: no inside listener".to_string(),
        ),
    }
    if let Some(path) = &inside_socket {
        let _ = std::fs::remove_file(path);
    }
    // The allow-list has to work too: a boundary that denied the session
    // directory would confine the host out of its own staging area.
    let writable = allowed_root.join("probe-writable");
    if let Err(error) = std::fs::create_dir(&writable) {
        failures.push(format!(
            "the session directory is not writable inside the sandbox: {error}"
        ));
    } else {
        let _ = std::fs::remove_dir(&writable);
    }
    if failures.is_empty() {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{PROBE_ACK}");
        let _ = out.flush();
        ExitCode::SUCCESS
    } else {
        for failure in &failures {
            eprintln!("sandbox probe failed: {failure}");
        }
        ExitCode::from(3)
    }
}

/// A check that must be denied: record the operation's name when it was not.
fn denied(failures: &mut Vec<String>, name: &str, result: std::io::Result<()>) {
    if result.is_ok() {
        failures.push(format!("{name} was not denied"));
    }
}

/// The outer half of the fork: wait for the confined child and mirror its exit.
///
/// This function never returns. A waiting shim rather than an exit-on-spawn is
/// what lets the supervisor observe the real exit status, and the child's
/// PDEATHSIG is what makes killing this shim kill the sandbox.
fn wait_shim(pid: libc::pid_t, cleanup: Option<&Path>) -> ! {
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            if let Some(path) = cleanup {
                let _ = std::fs::remove_dir_all(path);
            }
            if libc::WIFEXITED(status) {
                std::process::exit(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                // Mirror the signal rather than reporting a code, so the
                // supervisor sees the same termination the confined child had.
                let signal = libc::WTERMSIG(status);
                unsafe {
                    libc::signal(signal, libc::SIG_DFL);
                    libc::raise(signal);
                }
                std::process::exit(128 + signal);
            }
        } else if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("the sandbox wait shim lost the confined process: {error}");
            std::process::exit(1);
        }
    }
}

/// One deny-write that has to happen before the uid map is accepted.
fn write_proc(entry: &str, contents: &str) -> Result<(), String> {
    let path = format!("/proc/self/{entry}");
    match std::fs::write(&path, contents) {
        Ok(()) => Ok(()),
        // setgroups does not exist on kernels before its introduction; a map
        // without the denial is the unsafe case and still fails below.
        Err(error) if entry == "setgroups" && error.kind() == std::io::ErrorKind::NotFound => {
            Ok(())
        }
        Err(error) => Err(format!("could not write {path}: {error}")),
    }
}

/// The Landlock filesystem allow-list.
///
/// Everything reachable in the confined view that is not listed is denied,
/// because Landlock enforces the handled rights as a deny-by-default boundary.
/// The allow-list is the filesystem the host needs to be a host: the libraries
/// and loader a dynamic plugin links against, the resolver's own config, the
/// confined /proc of this PID namespace when it could be mounted (`have_proc`
/// — the mountpoint it never got is withheld instead of exposing the host's
/// process table), the minimal device files, and the one writable root — the
/// session directory.
fn landlock_restrict(allowed_root: &Path, have_proc: bool) -> Result<(), String> {
    const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const EXECUTE: u64 = 1 << 0;
    const WRITE_FILE: u64 = 1 << 1;
    const READ_FILE: u64 = 1 << 2;
    const READ_DIR: u64 = 1 << 3;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_BLOCK: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_SYM: u64 = 1 << 11;
    const REFER: u64 = 1 << 12; // ABI v2
    const TRUNCATE: u64 = 1 << 13; // ABI v3
    const IOCTL_DEV: u64 = 1 << 14; // ABI v5

    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi <= 0 {
        return Err(
            "Landlock is not available in this kernel (it needs Linux 5.13 or later built with \
             the Landlock LSM enabled), and without it the filesystem allow-list cannot be \
             enforced"
                .to_string(),
        );
    }
    // Only the rights this kernel knows may be handled.
    let handled: u64 = match abi {
        1 => {
            EXECUTE
                | WRITE_FILE
                | READ_FILE
                | READ_DIR
                | REMOVE_DIR
                | REMOVE_FILE
                | MAKE_CHAR
                | MAKE_BLOCK
                | MAKE_REG
                | MAKE_SOCK
                | MAKE_FIFO
                | MAKE_SYM
        }
        2 => {
            EXECUTE
                | WRITE_FILE
                | READ_FILE
                | READ_DIR
                | REMOVE_DIR
                | REMOVE_FILE
                | MAKE_CHAR
                | MAKE_BLOCK
                | MAKE_REG
                | MAKE_SOCK
                | MAKE_FIFO
                | MAKE_SYM
                | REFER
        }
        3 | 4 => {
            EXECUTE
                | WRITE_FILE
                | READ_FILE
                | READ_DIR
                | REMOVE_DIR
                | REMOVE_FILE
                | MAKE_CHAR
                | MAKE_BLOCK
                | MAKE_REG
                | MAKE_SOCK
                | MAKE_FIFO
                | MAKE_SYM
                | REFER
                | TRUNCATE
        }
        _ => {
            EXECUTE
                | WRITE_FILE
                | READ_FILE
                | READ_DIR
                | REMOVE_DIR
                | REMOVE_FILE
                | MAKE_CHAR
                | MAKE_BLOCK
                | MAKE_REG
                | MAKE_SOCK
                | MAKE_FIFO
                | MAKE_SYM
                | REFER
                | TRUNCATE
                | IOCTL_DEV
        }
    };
    let read_exec = (EXECUTE | READ_FILE | READ_DIR) & handled;
    let read_only = (READ_FILE | READ_DIR) & handled;
    let read_write_file = (READ_FILE | WRITE_FILE) & handled;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &RulesetAttr {
                handled_access_fs: handled,
            },
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    } as i32;
    if ruleset < 0 {
        return Err(format!(
            "could not create the filesystem ruleset: {}",
            std::io::Error::last_os_error()
        ));
    }

    #[repr(C)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }

    let rules: Vec<(PathBuf, u64)> = {
        let mut rules: Vec<(PathBuf, u64)> = vec![
            // The session directory: sockets, the staged artifact tree, and the
            // scratch the deployment gave this host as HOME.
            (allowed_root.to_path_buf(), handled),
        ];
        // Everything a dynamic plugin's own load and the runtime's steady state
        // legitimately reads. Nothing under an account's home is listed.
        for directory in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
            rules.push((PathBuf::from(directory), read_exec));
        }
        for directory in ["/etc/ld.so.conf.d"] {
            rules.push((PathBuf::from(directory), read_only));
        }
        if have_proc {
            rules.push((PathBuf::from("/proc"), read_only));
        }
        for file in [
            "/etc/ld.so.conf",
            "/etc/ld.so.cache",
            "/etc/passwd",
            "/etc/group",
            "/etc/nsswitch.conf",
        ] {
            rules.push((PathBuf::from(file), READ_FILE & handled));
        }
        for file in ["/dev/null", "/dev/full"] {
            rules.push((PathBuf::from(file), read_write_file));
        }
        for file in ["/dev/zero", "/dev/urandom", "/dev/random"] {
            rules.push((PathBuf::from(file), READ_FILE & handled));
        }
        rules
    };

    for (path, access) in &rules {
        let fd = unsafe {
            libc::open(
                std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(|_| format!("path is not usable: {}", path.display()))?
                    .as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            // A rule for something this system does not have — /lib64 on
            // Debian, /etc/ld.so.conf.d on a minimal image — is not a boundary
            // failure; the path simply grants nothing.
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            unsafe { libc::close(ruleset) };
            return Err(format!("could not open {}: {error}", path.display()));
        }
        let attr = PathBeneath {
            allowed_access: *access,
            parent_fd: fd,
        };
        let added = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr,
                0u32,
            )
        };
        unsafe { libc::close(fd) };
        if added != 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(ruleset) };
            return Err(format!(
                "could not add the ruleset rule for {}: {error}",
                path.display()
            ));
        }
    }

    let restricted = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) };
    unsafe { libc::close(ruleset) };
    if restricted != 0 {
        return Err(format!(
            "the filesystem allow-list could not be applied: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Install the syscall blocklist.
///
/// Default-allow with explicit `EPERM` denials: the set a plugin would call to
/// dismantle the confinement is finite and named, and a typo in an allow-list
/// is a broken host rather than a weaker boundary.
fn install_seccomp() -> Result<(), String> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ: u16 = 0x15;
    const BPF_JMP_JSET: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    const SECCOMP_RET_KILL: u32 = 0x80000000;
    const ERRNO: u32 = libc::EPERM as u32;

    // AUDIT_ARCH_* from linux/audit.h — stable kernel ABI values, kept local
    // because libc does not export them.
    #[cfg(target_arch = "x86_64")]
    const NATIVE_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const NATIVE_ARCH: u32 = 0xC000_00B7;

    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };

    let mut filter = vec![
        // An architecture that is not this build's makes syscall numbers
        // meaningless — this is the check that keeps a wrong-arch call from
        // slipping through a numbers table it was never written against.
        stmt(BPF_LD_W_ABS, 4), // seccomp_data.arch
        jump(BPF_JMP_JEQ, NATIVE_ARCH, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL),
        stmt(BPF_LD_W_ABS, 0), // seccomp_data.nr
        // The x32 ABI shares x86_64's arch but sets bit 30 on its syscall
        // numbers, which would read past this table's comparisons; a confined
        // host has no legitimate reason to make one.
        jump(BPF_JMP_JSET, 0x4000_0000, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_KILL),
        // sendto(fd, buf, len, flags, NULL, 0) is a connected-socket write and
        // the runtime needs it; sendto with a destination is the unconnected
        // reach the boundary forbids. The check reads args[4] — the sock_addr
        // pointer — which sits at byte offset 48 of seccomp_data, high word at
        // 52; a non-zero destination is denied, a NULL one falls through to
        // the remaining checks as if the call were `send`.
        jump(BPF_JMP_JEQ, libc::SYS_sendto as u32, 0, 6),
        stmt(BPF_LD_W_ABS, 48),
        jump(BPF_JMP_JEQ, 0, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | ERRNO),
        stmt(BPF_LD_W_ABS, 52),
        jump(BPF_JMP_JEQ, 0, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | ERRNO),
    ];
    for &number in BLOCKED_SYSCALLS {
        filter.push(jump(BPF_JMP_JEQ, number, 0, 1));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | ERRNO));
    }
    filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0 {
        return Err(format!(
            "could not install the syscall filter: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Drop the bounding set so no exec of anything — even if one were possible —
/// could carry a capability the sandbox granted this namespace.
fn drop_capabilities() {
    // CAP_CHECKPOINT_RESTORE, the last defined capability; prctl answers EINVAL
    // for any higher number a kernel does not know, so the loop is safe on
    // older kernels.
    const CAP_LAST_CAP: i32 = 40;
    for capability in 0..=CAP_LAST_CAP {
        unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0);
        }
    }
}
