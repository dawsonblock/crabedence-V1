// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

const CREDENTIALS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_CONFIG_FILE",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "CRABBOX_BROKER_TOKEN",
    "CRABBOX_EVIDENCE_KEY",
    "CRABBOX_OPENCOMPUTER_API_KEY",
    "CRABBOX_TEST_DATABASE_URL",
    "CRABBOX_TOKEN",
    "CRABEDENCE_DATABASE_URL",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENCOMPUTER_API_KEY",
];

/// A plugin subprocess must not inherit the operator's cloud credentials.
///
/// The `AWS_` prefix is forwarded for region and endpoint configuration, so
/// the credential names have to be excluded from both paths: the static
/// allowlist and the dynamic prefix.
#[test]
fn credential_names_are_never_forwarded() {
    let forwarded = forwarded_names_for_platform(
        CREDENTIALS.iter().map(|name| (*name).to_string()),
        None,
        false,
    );
    for name in CREDENTIALS {
        assert!(
            !forwarded.iter().any(|candidate| candidate == name),
            "{name} must not reach an MCP subprocess"
        );
    }

    // Configuration still flows: this is a credential boundary, not an
    // AWS ban.
    let configuration = ["AWS_REGION", "AWS_ENDPOINT_URL", "AWS_ROLE_ARN"];
    let forwarded = forwarded_names_for_platform(
        configuration.iter().map(|name| (*name).to_string()),
        None,
        false,
    );
    for name in configuration {
        assert!(
            forwarded.iter().any(|candidate| candidate == name),
            "{name} must still be forwarded"
        );
    }
}

/// A config that names a credential variable cannot reintroduce one.
#[test]
fn config_cannot_reintroduce_a_credential_name() {
    let config = serde_json::json!({ "secret_access_key_var": "AWS_SECRET_ACCESS_KEY" });
    let forwarded = forwarded_names_for_platform(std::iter::empty(), Some(&config), false);
    assert!(
        !forwarded.iter().any(|name| name == "AWS_SECRET_ACCESS_KEY"),
        "a config field must not be able to forward a blocked credential"
    );
}

/// The blocklist is authoritative, so the two lists cannot contradict.
#[test]
fn the_blocklist_wins_over_the_base_allowlist() {
    for name in BLOCKED_MCP_ENV_VARS {
        assert!(
            !BASE_MCP_ENV_VARS
                .iter()
                .any(|base| base.eq_ignore_ascii_case(name)),
            "{name} is blocked and must not also be allowlisted"
        );
    }
}

/// Home-pointer names must not be forwarded: forwarding them lets plugin
/// code rediscover the operator's credential files through ordinary
/// home-directory lookup.
#[test]
fn home_pointer_names_are_not_forwarded() {
    let environment = LEGACY_HOME_POINTER_MCP_ENV_VARS
        .iter()
        .map(|name| (*name).to_string());
    let forwarded = forwarded_names_for_platform(environment, None, false);
    for name in LEGACY_HOME_POINTER_MCP_ENV_VARS {
        assert!(
            !forwarded.iter().any(|candidate| candidate == name),
            "{name} must not reach an MCP subprocess"
        );
    }
}

/// Installs generated before the isolated-home boundary still validate:
/// their stale `env_vars` entries are tolerated as previously forwardable
/// because the runtime overrides them at process start anyway.
#[test]
fn retired_home_pointers_remain_previously_forwardable() {
    for name in LEGACY_HOME_POINTER_MCP_ENV_VARS {
        assert!(
            previously_forwardable_name_for_platform(name, false),
            "{name} should remain a tolerable historical extra"
        );
    }
}

/// A config field naming a home pointer cannot reintroduce it through
/// `env_vars` — the isolated home is what the subprocess will see.
#[test]
fn config_fields_cannot_reintroduce_home_pointers() {
    let config = serde_json::json!({
        "header_env": { "X-Home": "HOME" },
        "secret_access_key_var": "HOME"
    });
    let forwarded = forwarded_names_for_platform(std::iter::empty(), Some(&config), false);
    assert!(
        !forwarded.iter().any(|name| name == "HOME"),
        "a config field must not be able to forward a home pointer"
    );
}

#[test]
fn isolated_home_points_every_lookup_at_the_private_root() {
    let config_dir = PathBuf::from("/config/nemo-relay");
    let home = IsolatedHome::for_managed_mcp(config_dir.clone());
    let pairs: std::collections::BTreeMap<String, OsString> =
        home.env_pairs().into_iter().collect();
    let root = config_dir.join(ISOLATED_HOME_DIR);
    for (name, expected) in [
        ("HOME", root.clone()),
        ("USERPROFILE", root.clone()),
        ("APPDATA", root.join("AppData/Roaming")),
        ("LOCALAPPDATA", root.join("AppData/Local")),
        ("XDG_CONFIG_HOME", root.join(".config")),
        ("XDG_CACHE_HOME", root.join(".cache")),
        ("XDG_DATA_HOME", root.join(".local/share")),
        ("XDG_STATE_HOME", root.join(".local/state")),
        ("XDG_RUNTIME_DIR", root.join(".run")),
        (nemo_relay::plugin::USER_CONFIG_DIR_ENV, config_dir.clone()),
    ] {
        assert_eq!(
            pairs.get(name).map(OsString::as_os_str),
            Some(expected.as_os_str()),
            "{name} must resolve inside the isolated home"
        );
    }
    assert_eq!(home.root(), root.as_path());
}

/// The check the old residual comment could not make: a credential file in
/// the operator's real home is unreachable through ordinary home-directory
/// or XDG lookup once the isolated home applies.
#[cfg(unix)]
#[test]
fn spawned_subprocess_cannot_discover_credentials_in_the_real_home() {
    let real_home = tempfile::tempdir().expect("fake real home");
    let config_dir = real_home.path().join(".config").join("nemo-relay");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    for credential in [
        ".aws/credentials",
        ".ssh/id_rsa",
        ".config/gh/hosts.yml",
        ".git-credentials",
    ] {
        let path = real_home.path().join(credential);
        std::fs::create_dir_all(path.parent().expect("credential parent"))
            .expect("credential parent dir");
        std::fs::write(&path, b"secret\n").expect("fake credential");
    }

    let home = IsolatedHome::for_managed_mcp(config_dir);
    home.create().expect("create isolated home");

    // HOME-based lookup: nothing under the synthetic root exists except
    // what the isolated home created.
    let mut home_lookup = std::process::Command::new("/bin/sh");
    home_lookup
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-c")
        .arg(
            "for f in \"$HOME/.aws/credentials\" \"$HOME/.ssh/id_rsa\" \
            \"$HOME/.config/gh/hosts.yml\" \"$HOME/.git-credentials\"; do \
            if [ -f \"$f\" ]; then echo \"found $f\"; exit 1; fi; \
        done",
        );
    home.apply_to_command(&mut home_lookup);
    let output = home_lookup.output().expect("home lookup probe");
    assert!(
        output.status.success(),
        "subprocess observed real-home credentials: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // XDG-based lookup hits the same private root.
    let mut xdg_lookup = std::process::Command::new("/bin/sh");
    xdg_lookup
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-c")
        .arg("[ ! -f \"$XDG_CONFIG_HOME/gh/hosts.yml\" ]");
    home.apply_to_command(&mut xdg_lookup);
    assert!(
        xdg_lookup
            .output()
            .expect("xdg lookup probe")
            .status
            .success()
    );

    // The created root is owner-only.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(home.root())
        .expect("isolated root metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "isolated home must be owner-only");
}

/// The runtime enforcement: a managed launch (the generation fence is
/// present) swaps HOME for the private directory and pins the real config
/// directory for discovery.
#[test]
fn managed_launch_switches_to_the_isolated_home() {
    let base = tempfile::tempdir().expect("home base");
    let real_home = base.path().join("real-home");
    let config_dir = base.path().join("config").join("nemo-relay");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let generation = base.path().join("generation");
    std::fs::write(&generation, b"{}\n").expect("generation file");
    let _scope = crate::test_support::EnvScope::set(&[
        ("HOME", Some(real_home.as_os_str())),
        ("USERPROFILE", None),
        ("APPDATA", None),
        ("LOCALAPPDATA", None),
        ("XDG_CONFIG_HOME", None),
        ("XDG_CACHE_HOME", Some(std::ffi::OsStr::new("/real/cache"))),
        ("XDG_DATA_HOME", Some(std::ffi::OsStr::new("/real/data"))),
        ("XDG_STATE_HOME", Some(std::ffi::OsStr::new("/real/state"))),
        (
            "XDG_RUNTIME_DIR",
            Some(std::ffi::OsStr::new("/run/user/1000")),
        ),
        (
            nemo_relay::plugin::USER_CONFIG_DIR_ENV,
            Some(config_dir.as_os_str()),
        ),
        (GENERATION_FILE_ENV, Some(generation.as_os_str())),
        (GENERATION_TOKEN_ENV, Some(std::ffi::OsStr::new("token"))),
        (MCP_INHERIT_HOME_ENV, None),
        (MCP_REAL_HOME_ENV, None),
    ]);

    let root = enforce_managed_home_isolation()
        .expect("isolation should succeed")
        .expect("a managed launch must isolate");

    assert_eq!(root, config_dir.join(ISOLATED_HOME_DIR));
    assert_eq!(std::env::var_os("HOME").as_deref(), Some(root.as_os_str()));
    for name in [
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        let value = std::env::var_os(name).expect("xdg assignment");
        assert!(
            Path::new(&value).starts_with(&root),
            "{name} must resolve inside the isolated home, got {value:?}"
        );
    }
    // The pin keeps config discovery on the real directory.
    assert_eq!(
        crate::configuration::user_config_dir().expect("config dir"),
        config_dir
    );
}

/// An unmanaged `nemo-relay mcp` — no generation fence — keeps whatever
/// environment the operator ran it with.
#[test]
fn unmanaged_launch_keeps_the_ambient_environment() {
    let _scope = crate::test_support::EnvScope::set(&[
        (GENERATION_FILE_ENV, None),
        (GENERATION_TOKEN_ENV, None),
        (MCP_INHERIT_HOME_ENV, None),
    ]);
    let before = std::env::var_os("HOME");
    assert!(enforce_managed_home_isolation().unwrap().is_none());
    assert_eq!(std::env::var_os("HOME"), before);
}

/// The documented opt-out: `NEMO_RELAY_MCP_INHERIT_HOME=1` restores the
/// real home the generated contract recorded in `NEMO_RELAY_REAL_HOME`.
#[test]
fn inherit_home_opt_out_restores_the_real_home() {
    let base = tempfile::tempdir().expect("home base");
    let real_home = base.path().join("real-home");
    let synthetic = base.path().join("synthetic");
    let _scope = crate::test_support::EnvScope::set(&[
        ("HOME", Some(synthetic.as_os_str())),
        ("USERPROFILE", Some(synthetic.as_os_str())),
        (
            nemo_relay::plugin::USER_CONFIG_DIR_ENV,
            Some(base.path().as_os_str()),
        ),
        (GENERATION_FILE_ENV, Some(std::ffi::OsStr::new("/tmp/gen"))),
        (GENERATION_TOKEN_ENV, Some(std::ffi::OsStr::new("token"))),
        (MCP_INHERIT_HOME_ENV, Some(std::ffi::OsStr::new("1"))),
        (MCP_REAL_HOME_ENV, Some(real_home.as_os_str())),
    ]);
    assert!(enforce_managed_home_isolation().unwrap().is_none());
    assert_eq!(
        std::env::var_os("HOME").as_deref(),
        Some(real_home.as_os_str())
    );
}

/// A managed launch with no way to name the config directory fails closed
/// rather than running under the ambient home.
#[test]
fn managed_launch_without_a_config_dir_fails_closed() {
    let _scope = crate::test_support::EnvScope::set(&[
        ("HOME", None),
        ("USERPROFILE", None),
        ("XDG_CONFIG_HOME", None),
        (nemo_relay::plugin::USER_CONFIG_DIR_ENV, None),
        (GENERATION_FILE_ENV, Some(std::ffi::OsStr::new("/tmp/gen"))),
        (GENERATION_TOKEN_ENV, Some(std::ffi::OsStr::new("token"))),
        (MCP_INHERIT_HOME_ENV, None),
    ]);
    assert!(
        enforce_managed_home_isolation().is_err(),
        "a managed launch that cannot establish its private home must refuse"
    );
}

/// The generated launch contract carries the boundary in literals: the
/// installed file itself shows which home the subprocess gets.
#[test]
fn generated_env_literals_carry_the_isolation_boundary() {
    let base = tempfile::tempdir().expect("home base");
    let real_home = base.path().join("real-home");
    let config_dir = real_home.join(".config").join("nemo-relay");
    let _scope = crate::test_support::EnvScope::set(&[
        ("HOME", Some(real_home.as_os_str())),
        ("USERPROFILE", None),
        ("XDG_CONFIG_HOME", None),
        (nemo_relay::plugin::USER_CONFIG_DIR_ENV, None),
        (MCP_INHERIT_HOME_ENV, None),
    ]);

    let env = managed_home_env_literals();
    let root = config_dir.join(ISOLATED_HOME_DIR);
    assert_eq!(env["HOME"], serde_json::json!(root.to_string_lossy()));
    assert_eq!(
        env["XDG_CONFIG_HOME"],
        serde_json::json!(root.join(".config").to_string_lossy())
    );
    assert_eq!(
        env[nemo_relay::plugin::USER_CONFIG_DIR_ENV],
        serde_json::json!(config_dir.to_string_lossy())
    );
    assert_eq!(
        env[MCP_REAL_HOME_ENV],
        serde_json::json!(real_home.to_string_lossy())
    );
}

/// An opted-out install records the choice honestly: the literal block
/// names the real home instead of pretending isolation applies.
#[test]
fn opt_out_install_records_the_real_home() {
    let base = tempfile::tempdir().expect("home base");
    let real_home = base.path().join("real-home");
    let _scope = crate::test_support::EnvScope::set(&[
        ("HOME", Some(real_home.as_os_str())),
        ("USERPROFILE", None),
        (MCP_INHERIT_HOME_ENV, Some(std::ffi::OsStr::new("1"))),
    ]);

    let env = managed_home_env_literals();
    assert_eq!(env[MCP_INHERIT_HOME_ENV], serde_json::json!("1"));
    assert_eq!(
        env[MCP_REAL_HOME_ENV],
        serde_json::json!(real_home.to_string_lossy())
    );
    assert_eq!(env["HOME"], serde_json::json!(real_home.to_string_lossy()));
    assert!(
        env.get("XDG_CONFIG_HOME").is_none(),
        "an opt-out contract must not promise isolated XDG paths"
    );
}
