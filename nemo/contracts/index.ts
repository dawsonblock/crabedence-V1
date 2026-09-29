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
  ExecutionRoute,
  ExecutionStatus,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "./execution";

export {
  MAX_INVOCATION_DEPTH,
  validateInvocationRequest,
} from "./invocation-abi";
export type { InvocationValidation } from "./invocation-abi";
