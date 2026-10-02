// SPDX-License-Identifier: Apache-2.0

//! Routing decisions resolved from the verified registry.

use nemo_effect_router::testing::{RecordingBackend, catalog_for, descriptor, request_for};
use nemo_effect_router::{EffectRouter, RouteDecision};
use nemo_relay_executor::unstable::{ExecutionBackend, ExecutionClass, state_for_error};
use nemo_relay_ledger::unstable::ExecutionState;
use serde_json::json;

fn router(
    catalog: nemo_crabedence_bridge::capability_snapshot::VerifiedCapabilityCatalog,
) -> EffectRouter<RecordingBackend, RecordingBackend> {
    EffectRouter::new(
        catalog,
        RecordingBackend::default(),
        RecordingBackend::default(),
    )
}

#[test]
fn resolves_the_route_from_the_registry() {
    let catalog = catalog_for(json!([
        descriptor("pure.local", "PURE", "LOCAL"),
        descriptor("read.direct", "READ", "DIRECT"),
        descriptor("read.high", "READ", "CRABEDENCE"),
        descriptor("mutating", "MUTATION", "CRABEDENCE"),
        descriptor("critical", "CRITICAL", "CRABEDENCE"),
    ]));
    let router = router(catalog);
    assert_eq!(router.decide("pure.local").unwrap(), RouteDecision::Local);
    assert_eq!(router.decide("read.direct").unwrap(), RouteDecision::Direct);
    assert_eq!(
        router.decide("read.high").unwrap(),
        RouteDecision::Crabedence
    );
    assert_eq!(
        router.decide("mutating").unwrap(),
        RouteDecision::Crabedence
    );
    assert_eq!(
        router.decide("critical").unwrap(),
        RouteDecision::Crabedence
    );
}

#[test]
fn refuses_an_unregistered_capability() {
    let router = router(catalog_for(json!([descriptor(
        "pure.local",
        "PURE",
        "LOCAL"
    )])));
    let error = router.decide("not.registered").unwrap_err();
    assert_eq!(error.code, "CAPABILITY_NOT_FOUND");
    assert_eq!(state_for_error(&error), ExecutionState::Failed);
}

#[test]
fn refuses_a_local_route_for_a_non_pure_class() {
    // The registry refuses this at registration; a snapshot that carried it
    // anyway must fail closed rather than execute locally.
    let router = router(catalog_for(json!([descriptor(
        "sneaky.mutation",
        "MUTATION",
        "LOCAL"
    )])));
    let error = router.decide("sneaky.mutation").unwrap_err();
    assert_eq!(error.code, "EXECUTION_ROUTE_MISMATCH");
}

#[test]
fn pure_executes_locally() {
    let router = router(catalog_for(json!([descriptor(
        "pure.local",
        "PURE",
        "LOCAL"
    )])));
    let request = request_for("pure.local", ExecutionClass::Pure);
    let result = router.execute(&request).expect("executed");
    assert_eq!(result.output["entered"], true);
    assert_eq!(router.local().calls(), 1);
    assert_eq!(router.kernel().calls(), 0);
}

#[test]
fn a_read_pinned_to_the_kernel_crosses_it() {
    // The gap NeMo Relay's class-based router leaves: a READ can be pinned to
    // the CRABEDENCE route, and it must not take the local path.
    let router = router(catalog_for(json!([descriptor(
        "read.high",
        "READ",
        "CRABEDENCE"
    )])));
    let request = request_for("read.high", ExecutionClass::Read);
    router.execute(&request).expect("entered the kernel");
    assert_eq!(router.kernel().calls(), 1);
    assert_eq!(router.local().calls(), 0);
}

#[test]
fn refuses_a_class_downgrade_before_the_local_path() {
    let router = router(catalog_for(json!([descriptor(
        "pure.local",
        "PURE",
        "LOCAL"
    )])));
    // The registry pins PURE; the request asserts MUTATION. The route is
    // LOCAL, so the port's own check never runs — the router must catch it.
    let request = request_for("pure.local", ExecutionClass::Mutation);
    let error = router.execute(&request).unwrap_err();
    assert_eq!(error.code, "EXECUTION_CLASS_MISMATCH");
    assert_eq!(router.local().calls(), 0);
    assert_eq!(router.kernel().calls(), 0);
}

#[test]
fn a_read_pinned_direct_crosses_the_socket() {
    // DIRECT is the approved read path: the request crosses to the service,
    // whose dispatcher resolves the non-durable read route from its own
    // registry — not from anything the request asserts.
    let router = router(catalog_for(json!([descriptor(
        "read.direct",
        "READ",
        "DIRECT"
    )])));
    let request = request_for("read.direct", ExecutionClass::Read);
    router.execute(&request).expect("entered the kernel");
    assert_eq!(router.kernel().calls(), 1);
    assert_eq!(router.local().calls(), 0);
}

#[test]
fn refuses_a_consequential_class_on_the_direct_route() {
    // The registry refuses DIRECT for MUTATION at registration; a snapshot
    // that carried it anyway must fail closed rather than dispatch down the
    // non-durable route.
    let mut sneaky_critical = descriptor("sneaky.critical", "CRITICAL", "DIRECT");
    sneaky_critical["assurance_profile"] = json!("HIGH_ASSURANCE");
    let router = router(catalog_for(json!([
        descriptor("sneaky.mutation", "MUTATION", "DIRECT"),
        sneaky_critical,
    ])));
    for (id, class) in [
        ("sneaky.mutation", ExecutionClass::Mutation),
        ("sneaky.critical", ExecutionClass::Critical),
    ] {
        let request = request_for(id, class);
        let error = router.execute(&request).expect_err("must fail closed");
        assert_eq!(error.code, "EXECUTION_ROUTE_MISMATCH", "{id}");
    }
    assert_eq!(router.kernel().calls(), 0);
    assert_eq!(router.local().calls(), 0);
}

#[test]
fn refuses_durable_assurance_on_the_direct_route() {
    // DIRECT cannot carry DURABLE/HIGH_ASSURANCE at registration; the router
    // re-checks it rather than trusting the snapshot.
    let mut descriptor = descriptor("read.durable", "READ", "DIRECT");
    descriptor["assurance_profile"] = json!("DURABLE");
    let router = router(catalog_for(json!([descriptor])));
    let request = request_for("read.durable", ExecutionClass::Read);
    let error = router.execute(&request).unwrap_err();
    assert_eq!(error.code, "EXECUTION_ROUTE_MISMATCH");
    assert_eq!(router.kernel().calls(), 0);
}
