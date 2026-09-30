// SPDX-License-Identifier: Apache-2.0

//! Registry-pinned effect routing for the NeMo Relay kernel.
//!
//! [`EffectRouter`] is the single routing point between NeMo Relay and the
//! Crabedence execution kernel. It resolves where a capability executes from
//! the **verified registry snapshot** and never from the caller.
//!
//! # Why this exists next to NeMo Relay's own router
//!
//! NeMo Relay's kernel already routes by effect class: `PURE` and `READ` go to
//! the local function-hook backend, `MUTATION` and `CRITICAL` go to the
//! durable backend (`BackendRouter::execute_bound`). That is the right shape,
//! but the class is not the whole policy: Crabedence pins three independent
//! dimensions, and a `READ` capability may legitimately be pinned to the
//! `CRABEDENCE` route (`READ` + `HIGH_ASSURANCE`). A class-only router sends
//! that capability down the local path.
//!
//! This router resolves the **route**, which is the authoritative dimension,
//! and the registry's registration-time invariant does the rest:
//!
//! ```text
//! LOCAL      ⇒ PURE + NONE     (ValidateDescriptorCompatibility)
//! DIRECT     ⇒ READ            (and never MUTATION/CRITICAL)
//! CRABEDENCE ⇒ everything else
//! ```
//!
//! So "PURE executes locally, everything else crosses the kernel" is not a
//! convention this crate maintains — it is a consequence of the registry the
//! router trusts, and [`RouteDecision`] re-checks it anyway so a snapshot that
//! somehow violated it fails closed instead of executing.
//!
//! # The invariant
//!
//! > No execution path from NeMo Relay can produce an external `MUTATION` or
//! > `CRITICAL` effect without entering Crabedence's execution kernel.
//!
//! It is asserted by `tests/effect_isolation.rs` and by the CI job that runs
//! it, not merely documented here.
//!
//! # Composition
//!
//! The kernel's two backend slots both take this router, so whichever slot the
//! class-based rule selects, the route still decides:
//!
//! ```text
//! BackendRouter::new(authority, router.clone(), router)
//! ```
//!
//! The authority provider in that composition must not be NeMo Relay's own
//! authority implementation treated as the authority — Crabedence resolves
//! authority. A shim that defers (never denies on its own reasoning and never
//! grants more than it holds) is the correct filler: a denial there is safe
//! but a grant there is not a decision, only permission to ask.

use nemo_crabedence_bridge::capability_snapshot::{
    RegistryExecutionClass, RegistryExecutionRoute, VerifiedCapabilityCatalog,
};
use nemo_crabedence_bridge::execution_port::{NemoCrabedenceExecutionPort, registry_class_of};
use nemo_crabedence_bridge::outcome_mapping::refused_request;
use nemo_relay_executor::unstable::{
    EffectExecutionError, ExecutionBackend, ExecutionRequest, ExecutionResult,
};

pub mod testing;

/// Where one capability's execution is sent, resolved from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// Executes in this process. The registry guarantees `PURE` + `NONE`.
    Local,
    /// Crosses the Crabedence execution kernel.
    Crabedence,
    /// An approved read path, which this build does not wire.
    DirectUnavailable,
}

impl RouteDecision {
    /// Whether this decision leaves the process.
    pub const fn crosses_the_kernel(self) -> bool {
        matches!(self, Self::Crabedence)
    }
}

/// The single routing point between NeMo Relay and the Crabedence kernel.
///
/// `L` is the local backend (`PURE` capabilities only) and `K` is the
/// Crabedence execution backend. Both are injected so the routing decision can
/// be asserted against recording backends rather than inferred.
#[derive(Debug, Clone)]
pub struct EffectRouter<L, K> {
    catalog: VerifiedCapabilityCatalog,
    local: L,
    kernel: K,
}

/// The production router: local execution plus the Crabedence execution port.
pub type ProductionEffectRouter<L> = EffectRouter<L, NemoCrabedenceExecutionPort>;

impl<L, K> EffectRouter<L, K> {
    /// Builds a router from a verified catalog and the two backends.
    ///
    /// The catalog can only be produced by
    /// [`nemo_crabedence_bridge::capability_snapshot::load_catalog_from_snapshot`],
    /// so a router cannot be assembled around unverified descriptors.
    pub const fn new(catalog: VerifiedCapabilityCatalog, local: L, kernel: K) -> Self {
        Self {
            catalog,
            local,
            kernel,
        }
    }

    /// The verified catalog this router routes on.
    pub fn catalog(&self) -> &VerifiedCapabilityCatalog {
        &self.catalog
    }

    /// The local backend, so a caller can assert which path ran.
    pub const fn local(&self) -> &L {
        &self.local
    }

    /// The Crabedence execution backend, so a caller can assert which path ran.
    pub const fn kernel(&self) -> &K {
        &self.kernel
    }

    /// Resolves the route for one capability.
    ///
    /// Fails closed: an unregistered capability has no routing metadata, a
    /// `LOCAL` route is refused for anything but `PURE`, and an unwired read
    /// path is reported as unavailable rather than silently taking a different
    /// path.
    pub fn decide(&self, capability_id: &str) -> Result<RouteDecision, EffectExecutionError> {
        let descriptor = self.catalog.descriptor(capability_id).ok_or_else(|| {
            refused_request(
                "CAPABILITY_NOT_FOUND",
                format!(
                    "capability {capability_id} is not in the verified registry snapshot — no routing metadata exists for it"
                ),
            )
        })?;
        match descriptor.execution_route {
            RegistryExecutionRoute::Local => {
                // The registry refuses LOCAL for anything but PURE + NONE at
                // registration. Re-checking here means a snapshot that somehow
                // carried it fails closed instead of executing locally.
                if descriptor.execution_class != RegistryExecutionClass::Pure {
                    return Err(refused_request(
                        "EXECUTION_ROUTE_MISMATCH",
                        format!(
                            "capability {capability_id} is pinned LOCAL but classified {} — LOCAL execution is only legal for PURE",
                            descriptor.execution_class
                        ),
                    ));
                }
                Ok(RouteDecision::Local)
            }
            RegistryExecutionRoute::Crabedence => Ok(RouteDecision::Crabedence),
            RegistryExecutionRoute::Direct => Ok(RouteDecision::DirectUnavailable),
        }
    }

    /// Reports whether the capability's asserted class agrees with the
    /// registry's pinned class.
    fn class_agrees(
        &self,
        request: &ExecutionRequest,
        capability_id: &str,
    ) -> Result<(), EffectExecutionError> {
        let descriptor = self
            .catalog
            .descriptor(capability_id)
            .ok_or_else(|| refused_request("CAPABILITY_NOT_FOUND", capability_id.to_string()))?;
        let registered = descriptor.execution_class;
        let asserted = registry_class_of(request.identity.capability.execution_class);
        if registered != asserted {
            return Err(refused_request(
                "EXECUTION_CLASS_MISMATCH",
                format!(
                    "capability {capability_id} is registered as {registered} but the request asserted {asserted} — the registry is authoritative"
                ),
            ));
        }
        Ok(())
    }
}

impl<L, K> ExecutionBackend for EffectRouter<L, K>
where
    L: ExecutionBackend,
    K: ExecutionBackend,
{
    /// Dispatches one already-bound execution to the path its registry
    /// descriptor pins.
    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> {
        let capability_id = request.identity.capability.capability_id.clone();
        match self.decide(&capability_id)? {
            RouteDecision::Local => {
                self.class_agrees(request, &capability_id)?;
                self.local.execute(request)
            }
            RouteDecision::Crabedence => self.kernel.execute(request),
            RouteDecision::DirectUnavailable => Err(refused_request(
                "CAPABILITY_UNAVAILABLE",
                format!(
                    "capability {capability_id} is pinned to the DIRECT route and no approved read path is wired in this build"
                ),
            )),
        }
    }
}
