/**
 * NeMo execution contracts — public surface.
 *
 * These types are frozen. The kernel, adapters, and Crabedence all
 * depend on them. Breaking changes require a new contract version.
 */
export type {
  AuthorityRef,
  CapabilityDescriptor,
  ExecutionClass,
  ExecutionEvidence,
  ExecutionMeta,
  ExecutionPort,
  ExecutionStatus,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "./execution";
