// SPDX-License-Identifier: Apache-2.0

//! The effect-isolation invariant.
//!
//! > No execution path from NeMo Relay can produce an external `MUTATION` or
//! > `CRITICAL` effect without entering Crabedence's execution kernel.
//!
//! This is the property the whole consolidation rests on, so it is asserted
//! here rather than documented. The assertion is about *which backend ran*,
//! which is why the router injects its backends instead of hiding them: a
//! recording backend is the evidence, and "the local backend was never
//! entered" is checked directly rather than inferred from an error code.
//!
//! Three layers are covered:
//!
//! 1. every legal consequential capability resolves to the kernel;
//! 2. no consequential dispatch enters the local backend;
//! 3. a registry that violated its own registration invariant — a `MUTATION`
//!    or `CRITICAL` capability pinned to `LOCAL` — fails closed rather than
//!    executing, and a capability absent from the registry executes nowhere.

use std::path::PathBuf;

use nemo_crabedence_bridge::capability_snapshot::load_catalog_from_path;
use nemo_effect_router::testing::{RecordingBackend, catalog_for, descriptor, request_for};
use nemo_effect_router::{EffectRouter, RouteDecision};
use nemo_relay_executor::unstable::{ExecutionBackend, ExecutionClass};
use serde_json::json;

type TestRouter = EffectRouter<RecordingBackend, RecordingBackend>;

fn router(
    catalog: nemo_crabedence_bridge::capability_snapshot::VerifiedCapabilityCatalog,
) -> TestRouter {
    EffectRouter::new(
        catalog,
        RecordingBackend::default(),
        RecordingBackend::default(),
    )
}

/// Every capability class and route combination the registry permits.
fn legal_registry() -> serde_json::Value {
    json!([
        descriptor("pure.local", "PURE", "LOCAL"),
        descriptor("pure.direct", "PURE", "DIRECT"),
        descriptor("read.direct", "READ", "DIRECT"),
        descriptor("read.high", "READ", "CRABEDENCE"),
        descriptor("mutating", "MUTATION", "CRABEDENCE"),
        descriptor("critical", "CRITICAL", "CRABEDENCE"),
    ])
}

/// The asserted class for a capability, as a request would carry it.
fn class_of(id: &str) -> ExecutionClass {
    match id {
        "pure.local" | "pure.direct" => ExecutionClass::Pure,
        "read.direct" | "read.high" => ExecutionClass::Read,
        "mutating" => ExecutionClass::Mutation,
        _ => ExecutionClass::Critical,
    }
}

#[test]
fn every_consequential_capability_resolves_to_the_kernel() {
    let router = router(catalog_for(legal_registry()));
    for id in ["mutating", "critical"] {
        assert_eq!(
            router.decide(id).expect("registered"),
            RouteDecision::Crabedence,
            "{id} must resolve to the kernel"
        );
        assert!(router.decide(id).expect("registered").crosses_the_kernel());
    }
}

#[test]
fn no_consequential_effect_reaches_the_local_backend() {
    let router = router(catalog_for(legal_registry()));
    let consequential = ["mutating", "critical"];

    for id in consequential {
        let request = request_for(id, class_of(id));
        router.execute(&request).expect("entered the kernel");
    }

    assert_eq!(
        router.local().calls(),
        0,
        "no MUTATION or CRITICAL capability may enter the local backend"
    );
    assert_eq!(
        router.kernel().calls(),
        consequential.len(),
        "every consequential capability must have crossed the kernel"
    );
}

#[test]
fn only_pure_capabilities_reach_the_local_backend() {
    let router = router(catalog_for(legal_registry()));
    let request = request_for("pure.local", ExecutionClass::Pure);
    router.execute(&request).expect("executed locally");

    assert_eq!(router.local().calls(), 1);
    assert_eq!(
        router.kernel().calls(),
        0,
        "a PURE capability pinned LOCAL must not cross the kernel"
    );
}

#[test]
fn a_registry_that_violates_its_own_invariant_fails_closed() {
    // The registry refuses LOCAL for anything but PURE at registration, so
    // these cannot occur in a real snapshot. If one ever did — a loader bug, a
    // future relaxation — the router must refuse rather than execute.
    let router = router(catalog_for(json!([
        descriptor("sneaky.mutation", "MUTATION", "LOCAL"),
        descriptor("sneaky.critical", "CRITICAL", "LOCAL"),
    ])));

    for id in ["sneaky.mutation", "sneaky.critical"] {
        let request = request_for(id, class_of(id));
        let error = router.execute(&request).expect_err("must fail closed");
        assert_eq!(error.code, "EXECUTION_ROUTE_MISMATCH", "{id}");
    }

    assert_eq!(router.local().calls(), 0);
    assert_eq!(router.kernel().calls(), 0);
}

#[test]
fn an_unregistered_capability_executes_nowhere() {
    let router = router(catalog_for(legal_registry()));
    let request = request_for("github.issue.create", ExecutionClass::Mutation);
    let error = router.execute(&request).expect_err("must fail closed");

    assert_eq!(error.code, "CAPABILITY_NOT_FOUND");
    assert_eq!(router.local().calls(), 0);
    assert_eq!(router.kernel().calls(), 0);
}

/// The invariant against a real registry, not a fixture.
///
/// Gated on `NEMO_CRABEDENCE_LIVE_SOCKET`, the path to a running
/// `crabbox serve-exec` socket: the assertion is about the registry the
/// service actually ships, which is the one that matters.
#[test]
fn the_live_registry_pins_every_consequential_capability_to_the_kernel() {
    let Some(socket) = std::env::var_os("NEMO_CRABEDENCE_LIVE_SOCKET") else {
        eprintln!(
            "skipping live registry check: set NEMO_CRABEDENCE_LIVE_SOCKET to a running \
             `crabbox serve-exec` socket to enable it"
        );
        return;
    };
    let snapshot = PathBuf::from(socket)
        .parent()
        .expect("socket has a parent directory")
        .join("capabilities.json");
    let catalog = load_catalog_from_path(&snapshot).expect("the service's own snapshot verifies");
    let router = router(catalog);

    let mut consequential = 0;
    for descriptor in router.catalog().descriptors() {
        if matches!(
            descriptor.execution_class,
            nemo_crabedence_bridge::capability_snapshot::RegistryExecutionClass::Mutation
                | nemo_crabedence_bridge::capability_snapshot::RegistryExecutionClass::Critical
        ) {
            consequential += 1;
            assert_eq!(
                router.decide(&descriptor.id).expect("registered"),
                RouteDecision::Crabedence,
                "{} is {} and must resolve to the kernel",
                descriptor.id,
                descriptor.execution_class
            );
        }
    }
    assert!(
        consequential > 0,
        "the live registry must contain at least one consequential capability, \
         otherwise this check proves nothing"
    );
    println!("live registry: {consequential} consequential capabilities, all kernel-routed");
}
