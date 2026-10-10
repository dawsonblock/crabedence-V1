// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared support for Rust tests of the Python binding.

use std::ffi::{CString, OsString};
use std::sync::{Mutex, MutexGuard, OnceLock};

use pyo3::prelude::*;
use pyo3::types::PyModule;

const BINDING_KIND_ENV: &str = "NEMO_RELAY_BINDING_KIND";
const RUNTIME_OWNER_ENV: &str = "NEMO_RELAY_RUNTIME_OWNER";
const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";

fn python_test_lock() -> &'static Mutex<()> {
    static PYTHON_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    PYTHON_TEST_LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) fn lock_python_test() -> MutexGuard<'static, ()> {
    python_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clear_runtime_owner_env() {
    unsafe {
        std::env::remove_var(RUNTIME_OWNER_ENV);
        std::env::remove_var(BINDING_KIND_ENV);
    }
}

pub(crate) struct PythonTestGuard {
    _lock: MutexGuard<'static, ()>,
    binding_kind: Option<OsString>,
    runtime_owner: Option<OsString>,
    xdg_config_home: Option<OsString>,
}

impl Drop for PythonTestGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.runtime_owner {
                Some(value) => std::env::set_var(RUNTIME_OWNER_ENV, value),
                None => std::env::remove_var(RUNTIME_OWNER_ENV),
            };
            match &self.binding_kind {
                Some(value) => std::env::set_var(BINDING_KIND_ENV, value),
                None => std::env::remove_var(BINDING_KIND_ENV),
            };
            match &self.xdg_config_home {
                Some(value) => std::env::set_var(XDG_CONFIG_HOME_ENV, value),
                None => std::env::remove_var(XDG_CONFIG_HOME_ENV),
            };
        }
    }
}

pub(crate) fn init_python_test_locked(lock: MutexGuard<'static, ()>) -> PythonTestGuard {
    let binding_kind = std::env::var_os(BINDING_KIND_ENV);
    let runtime_owner = std::env::var_os(RUNTIME_OWNER_ENV);
    let xdg_config_home = std::env::var_os(XDG_CONFIG_HOME_ENV);
    clear_runtime_owner_env();
    let isolated_config_home =
        std::env::temp_dir().join(format!("nemo-relay-python-tests-{}", std::process::id()));
    unsafe {
        std::env::set_var(XDG_CONFIG_HOME_ENV, isolated_config_home);
    }
    Python::initialize();
    // The pyo3 async runtime is a process-wide OnceLock: the first
    // `get_runtime()` call freezes it for the whole test binary. `_native`
    // module init installs the 8 MiB worker stack, but a test that reaches the
    // async path before any `_native` call freezes the lazy default (2 MiB)
    // instead — which is where the guardrails coverage tests overflowed. This
    // lock serializes python tests, so initializing here pins the sized
    // runtime before any test can freeze the default.
    pyo3_async_runtimes::tokio::init({
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder
            .enable_all()
            .thread_stack_size(crate::PYTHON_FUTURE_STACK_BYTES);
        builder
    });
    let _ = pyo3_async_runtimes::tokio::get_runtime();
    Python::attach(|py| {
        let sys_modules = py
            .import("sys")
            .expect("import sys")
            .getattr("modules")
            .expect("sys.modules");
        if sys_modules
            .contains("nemo_relay._event_sanitizer_context")
            .expect("inspect test modules")
        {
            return;
        }
        let package = PyModule::new(py, "nemo_relay").expect("create test package");
        package
            .setattr("__path__", Vec::<String>::new())
            .expect("mark test package");
        sys_modules
            .set_item("nemo_relay", package)
            .expect("register test package");
        let source = CString::new(include_str!(
            "../../../../python/nemo_relay/_event_sanitizer_context.py"
        ))
        .expect("helper source");
        let filename = CString::new("_event_sanitizer_context.py").expect("helper filename");
        let module_name =
            CString::new("nemo_relay._event_sanitizer_context").expect("helper module name");
        let helper = PyModule::from_code(py, &source, &filename, &module_name)
            .expect("load async callback helpers");
        sys_modules
            .set_item("nemo_relay._event_sanitizer_context", helper)
            .expect("register async callback helpers");
    });
    PythonTestGuard {
        _lock: lock,
        binding_kind,
        runtime_owner,
        xdg_config_home,
    }
}

pub(crate) fn init_python_test() -> PythonTestGuard {
    init_python_test_locked(lock_python_test())
}

/// Runs a test body on a thread with the stack a deep managed call needs.
///
/// A managed call that reaches Python callbacks runs through bounded but deep
/// layers — `block_on` polls, middleware invokes the Python callback, and the
/// callback re-enters the runtime inside the same chain — which measurably
/// exceeds the ~2 MiB stack libtest gives a test thread. The binding's own
/// runtime workers already carry `PYTHON_FUTURE_STACK_BYTES` for the same
/// reason; tests that host the call on the test thread get the same budget
/// here, stated in one place rather than smuggled through RUST_MIN_STACK.
pub(crate) fn with_test_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(crate::PYTHON_FUTURE_STACK_BYTES)
        .spawn(test)
        .expect("the test thread spawns")
        .join()
        .expect("the test body completes");
}
