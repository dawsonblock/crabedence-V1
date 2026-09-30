// SPDX-License-Identifier: Apache-2.0

//! The Crabedence execution-port bridge.
//!
//! This crate connects the NeMo Relay kernel to the Crabedence execution
//! kernel. It is deliberately tiny, and it is a transport and mapping layer —
//! nothing else.
//!
//! It does **not** own:
//!
//! - provider semantics,
//! - authority truth (grant resolution is Crabedence's job),
//! - execution-class truth (Crabedence's registry is authoritative),
//! - durable idempotency,
//! - receipts or evidence,
//! - reconciliation.
//!
//! # Trust boundary
//!
//! NeMo Relay decides how to run, reason, and route. Crabedence decides whether
//! consequential work is authorized and how it is committed. The only seam is
//! the capability invocation ABI
//! (`docs/spec/capability-invocation-abi.md` in the Crabedence repository).
//!
//! The request that crosses the boundary carries the capability, its
//! arguments, authority material, an idempotency key, and a deadline. It never
//! carries execution route, provider selection, assurance profile, approval
//! requirements, retry policy, or receipt requirements: those are resolved by
//! the authoritative registry, and a planner that supplies them is refused.
//!
//! # Uncertainty
//!
//! The durable execution contract's dispatch boundary is preserved exactly:
//! a failure before the request frame is fully transmitted is a definitive
//! pre-dispatch failure, while anything after transmission is ambiguous and
//! must be reconciled, never retried. [`transport::TransportErrorKind`] carries
//! that classification and [`outcome_mapping`] translates it into NeMo Relay's
//! [`nemo_relay_executor::unstable::EffectExecutionError`] vocabulary, so
//! [`nemo_relay_executor::unstable::state_for_error`] reaches the same
//! conclusion the Crabedence kernel did.
//!
//! # Modules
//!
//! - [`abi`] — the strict invocation-ABI scanner (rules R1–R8), a Rust mirror
//!   of the Go parser and the NEMO TypeScript validator. All three consume the
//!   shared conformance corpus and must accept or reject identically.
//! - [`transport`] — the length-prefixed JSON Unix-socket client and its
//!   dispatch-boundary classification.
//! - [`capability_snapshot`] — verification of the registry envelope
//!   (`capabilities.json`) before any descriptor is parsed.
//! - [`outcome_mapping`] — Crabedence wire outcomes mapped onto NeMo Relay's
//!   execution result and error contracts.
//! - [`execution_port`] — [`execution_port::NemoCrabedenceExecutionPort`],
//!   the [`nemo_relay_executor::unstable::ExecutionBackend`] implementation.

pub mod abi;
pub mod capability_snapshot;
pub mod execution_port;
pub mod outcome_mapping;
pub mod transport;

pub use capability_snapshot::{
    RegistryDescriptor, RegistryEnvelope, SnapshotError, VerifiedCapabilityCatalog,
    load_catalog_from_snapshot,
};
pub use execution_port::{NemoCrabedenceExecutionPort, registry_class_of};
pub use outcome_mapping::{ExecutionOutcome, map_outcome, map_transport_failure, refused_request};
pub use transport::{ExecutionSocketClient, TransportError, TransportErrorKind};
