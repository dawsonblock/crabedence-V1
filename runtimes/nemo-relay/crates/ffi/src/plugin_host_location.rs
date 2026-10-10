// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Where this library's plugin host is, when nothing named one.
//!
//! The FFI has no package of its own the way the Node and Python bindings do:
//! what a deployment installs is the shared library plus its companions. So the
//! one place a host can live without being named is beside that library — the
//! directory the loader mapped `libnemo_relay_ffi` from — and `dladdr` is what
//! lets the library ask which file it came from rather than guessing from the
//! process that happens to be running.
//!
//! `NEMO_RELAY_PLUGIN_HOST` stays authoritative: a deployment that names a host
//! gets that host or a failure, never a quiet fallback to whichever companion
//! the library happens to sit beside.

use std::path::PathBuf;

/// The host a deployment reaches when it carries one beside the library.
///
/// `None` only when the loader cannot name this library's file or no companion
/// sits beside it — which leaves the runtime's own beside-the-process rule in
/// place, the answer a source deployment gets today.
pub(crate) fn resolved_host() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os(nemo_relay_plugin_host::supervisor::EXECUTABLE_ENV) {
        return Some(PathBuf::from(configured));
    }
    beside_this_library()
}

#[cfg(unix)]
fn beside_this_library() -> Option<PathBuf> {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let found = unsafe { libc::dladdr(dladdr_anchor as *const libc::c_void, &mut info) };
    if found == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
        .to_str()
        .ok()?;
    // The directory the library was mapped from, then the one above it: a cargo
    // build links the copy under `deps/` while the host it ships beside sits in
    // the profile directory — the same pair of places `beside_directories`
    // gives the process-level rule.
    let directory = PathBuf::from(path).parent()?.to_path_buf();
    for candidate_dir in
        std::iter::once(directory.clone()).chain(directory.parent().map(PathBuf::from))
    {
        let candidate = candidate_dir.join("nemo-plugin-host");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A symbol this library owns, to anchor the `dladdr` lookup.
///
/// The address has to be *this* library's rather than an arbitrary code pointer:
/// `dladdr` reports which file mapped the address it is given, so asking through
/// a dependency would resolve the dependency's directory instead.
#[cfg(unix)]
extern "C" fn dladdr_anchor() {}

#[cfg(not(unix))]
fn beside_this_library() -> Option<PathBuf> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_anchor_resolves_to_a_directory_that_exists() {
        // On a unix build the anchor lands in whatever mapped this crate — a
        // test binary rather than the shared library, since cargo test links
        // statically. The directory it reports therefore is real either way;
        // what the library's *directory* then holds is a property of the
        // installation, not of this lookup.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        let found = unsafe { libc::dladdr(dladdr_anchor as *const libc::c_void, &mut info) };
        assert!(found != 0, "dladdr could not place this library");
        assert!(!info.dli_fname.is_null());
        let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
            .to_str()
            .expect("a library path is UTF-8 on supported unix targets");
        let directory = PathBuf::from(path)
            .parent()
            .expect("a loaded library has a directory")
            .to_path_buf();
        assert!(directory.is_dir(), "{directory:?} does not exist");
        assert_ne!(
            PathBuf::from(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default(),
            "",
            "the anchor's file should have a name"
        );
    }
}
