/**
 * NeMo execution contracts.
 *
 * These types define the boundary between NeMo (reasoning/kernel) and
 * Crabedence (execution-control). NeMo owns these interfaces. Crabedence
 * implements them through an adapter.
 *
 * Dependency direction:
 *
 *   NeMo contract
 *       ↑
 *   Crabedence adapter
 *
 * Never the reverse.
 */

// ─── Execution classes ────────────────────────────────────────────────

/**
 * Execution class determines how a capability is routed and what safety
 * guarantees apply. The class is pinned at capability registration time
 * and cannot be downgraded at runtime.
 *
 * PURE     — no side effects, executes locally in NeMo
 * READ     — side-effect-free reads, routed through Crabedence fast path
 * MUTATION — side-effectful operations, routed through Crabedence guarded path
 * CRITICAL — side-effectful operations requiring durable evidence + receipts
 */
export type ExecutionClass = "PURE" | "READ" | "MUTATION" | "CRITICAL";

// ─── Authority ────────────────────────────────────────────────────────

/**
 * Authority reference. NeMo requests authority; it does not invent it.
 * Crabedence verifies that the grant is valid before executing.
 */
export interface AuthorityRef {
  /** Principal requesting execution (e.g. "user:alice@example.com"). */
  readonly principal: string;
  /** Grant identifier issued by the authority service. */
  readonly grantId: string;
}

// ─── Execution request ────────────────────────────────────────────────

/**
 * Request to execute a capability through the kernel.
 *
 * NeMo constructs this. The kernel routes it to the appropriate adapter
 * based on the capability's pinned execution class.
 */
export interface KernelExecutionRequest {
  /** Registered capability identifier (e.g. "email.send"). */
  readonly capabilityId: string;
  /** Arguments matching the capability's JSON schema. */
  readonly arguments: unknown;
  /** Authority under which the capability is invoked. */
  readonly authority: AuthorityRef;
  /**
   * Execution class override. If provided, must match the capability's
   * registered class — cannot downgrade. If omitted, the registered class
   * is used.
   */
  readonly executionClass?: ExecutionClass;
  /** Idempotency key for mutations. Prevents duplicate side effects. */
  readonly idempotencyKey?: string;
  /** Optional deadline (ISO 8601). Crabedence rejects after this time. */
  readonly deadline?: string;
}

// ─── Execution outcome ───────────────────────────────────────────────

/**
 * Terminal status of an execution.
 *
 * SUCCEEDED — the capability completed successfully.
 * FAILED    — the capability completed with an error.
 * DENIED    — authority was not sufficient or was revoked.
 * UNKNOWN   — the capability was invoked but the outcome could not be
 *             confirmed. This is a first-class terminal state for
 *             side-effectful operations. NeMo must NOT retry UNKNOWN
 *             results for MUTATION/CRITICAL capabilities, as the side
 *             effect may have already occurred.
 */
export type ExecutionStatus = "SUCCEEDED" | "FAILED" | "DENIED" | "UNKNOWN";

/**
 * Evidence reference produced by Crabedence. NeMo stores this but does
 * not generate or verify it.
 */
export interface ExecutionEvidence {
  /** SHA-256 digest of the canonical RunEvidenceV1. */
  readonly digest: string;
  /** Receipt schema version (3 for evidence-bound receipts). */
  readonly receiptVersion?: number;
}

/**
 * Execution metadata returned by Crabedence.
 */
export interface ExecutionMeta {
  /** Provider that executed the capability. */
  readonly provider: string;
  /** Run identifier assigned by Crabedence. */
  readonly runId: string;
}

/**
 * Terminal outcome of an execution request.
 */
export interface KernelExecutionOutcome {
  readonly status: ExecutionStatus;
  /** Result payload on SUCCEEDED. */
  readonly result?: unknown;
  /** Error message on FAILED or DENIED. */
  readonly error?: string;
  /** Evidence reference on SUCCEEDED/UNKNOWN for CRITICAL class. */
  readonly evidence?: ExecutionEvidence;
  /** Execution metadata. */
  readonly execution?: ExecutionMeta;
}

// ─── Execution port ──────────────────────────────────────────────────

/**
 * The execution port. NeMo's kernel depends on this interface, not on
 * Crabedence directly. Multiple adapters can implement it:
 *
 *   - LocalExecutionAdapter (PURE capabilities)
 *   - MockExecutionAdapter (testing)
 *   - CrabedenceExecutionAdapter (production)
 */
export interface ExecutionPort {
  execute(request: KernelExecutionRequest): Promise<KernelExecutionOutcome>;
}

// ─── Capability descriptor ────────────────────────────────────────────

/**
 * Describes a registered capability. The execution class is immutable
 * once registered — no runtime downgrades.
 */
export interface CapabilityDescriptor {
  /** Unique capability identifier. */
  readonly id: string;
  /** JSON schema for arguments validation. */
  readonly schema: unknown;
  /** Pinned execution class. Cannot be changed after registration. */
  readonly executionClass: ExecutionClass;
  /** Adapter that handles this capability (e.g. "local", "crabedence"). */
  readonly adapter: string;
  /** Authority policy identifier (e.g. "communications.email.send"). */
  readonly authorityPolicy: string;
}
