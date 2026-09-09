/**
 * NEMO kernel — capability catalog and execution routing.
 *
 * NEMO is an optional specialized reasoning/research component, not the
 * parent runtime. Any planner can invoke Crabedence capabilities through
 * the stable capability invocation ABI (docs/spec/capability-invocation-abi.md).
 *
 * The kernel owns:
 *   - capability registration (with pinned execution classes for NEMO-local routing)
 *   - execution class routing (PURE → local, READ/MUTATION/CRITICAL → adapter)
 *   - request admission (schema validation, authority policy binding,
 *     deadline enforcement, CRITICAL evidence verification)
 *
 * The kernel does NOT own:
 *   - provider lifecycle
 *   - evidence generation
 *   - receipt signing
 *   - PostgreSQL fencing
 *   - idempotency storage
 *   - authority truth (grant resolution)
 *   - execution-class truth (Crabedence's registry is authoritative)
 *
 * Those are Crabedence's responsibilities below the port.
 */

import type {
  CapabilityDescriptor,
  ExecutionClass,
  ExecutionPort,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../contracts/index";

// ─── Capability registry ──────────────────────────────────────────────

/**
 * Immutable capability catalog. Once a capability is registered, its
 * execution class cannot be changed. This prevents runtime downgrades
 * (e.g. a model prompt cannot downgrade CRITICAL to READ for speed).
 */
export class CapabilityCatalog {
  private readonly capabilities = new Map<string, CapabilityDescriptor>();

  register(descriptor: CapabilityDescriptor): void {
    if (this.capabilities.has(descriptor.id)) {
      throw new Error(`capability already registered: ${descriptor.id}`);
    }
    // Deep freeze the descriptor and its schema to prevent mutation
    this.capabilities.set(descriptor.id, deepFreeze(structuredClone(descriptor)));
  }

  lookup(capabilityId: string): CapabilityDescriptor {
    const descriptor = this.capabilities.get(capabilityId);
    if (!descriptor) {
      throw new Error(`unknown capability: ${capabilityId}`);
    }
    return descriptor;
  }

  has(capabilityId: string): boolean {
    return this.capabilities.has(capabilityId);
  }

  list(): CapabilityDescriptor[] {
    return [...this.capabilities.values()];
  }
}

/** Deep freeze an object and all nested properties. */
function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    Object.freeze(value);
    for (const key of Object.keys(value as object)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
  }
  return value;
}

// ─── Schema validation ────────────────────────────────────────────────

/**
 * Minimal JSON schema validation for the subset of JSON schema used in
 * capability descriptors. This is NOT a full JSON schema implementation —
 * it validates type, required properties, and basic constraints. For
 * full schema validation, Crabedence's core should validate at execution
 * time. The kernel validates enough to reject obviously malformed
 * requests before they reach the execution port.
 */
function validateSchema(value: unknown, schema: unknown): string | null {
  if (!schema || typeof schema !== "object") {
    return null; // No schema = no validation
  }
  const s = schema as Record<string, unknown>;

  if (s.type === "object" && typeof value !== "object") {
    return `expected object, got ${typeof value}`;
  }
  if (s.type === "string" && typeof value !== "string") {
    return `expected string, got ${typeof value}`;
  }
  if (s.type === "number" && typeof value !== "number") {
    return `expected number, got ${typeof value}`;
  }
  if (s.type === "boolean" && typeof value !== "boolean") {
    return `expected boolean, got ${typeof value}`;
  }
  if (s.type === "array" && !Array.isArray(value)) {
    return `expected array, got ${typeof value}`;
  }

  if (s.required && Array.isArray(s.required) && typeof value === "object" && value) {
    for (const prop of s.required as string[]) {
      if (!(prop in value)) {
        return `missing required property: ${prop}`;
      }
    }
  }

  return null;
}

// ─── Deadline validation ──────────────────────────────────────────────

/**
 * Validate and check a deadline string. Returns:
 *   - null if no deadline or deadline is valid and not expired
 *   - error message if deadline is malformed or expired
 *
 * Uses RFC3339 parsing to match Go's time.Parse(time.RFC3339, ...).
 * Date.parse accepts formats that Go's RFC3339 parser will reject,
 * so we validate the format more strictly here.
 */
function checkDeadline(deadline: string | undefined): string | null {
  if (!deadline) {
    return null;
  }
  // RFC3339: YYYY-MM-DDTHH:MM:SS[.ssssss](Z|+HH:MM|-HH:MM)
  // This is a strict check that rejects what Go would reject.
  const rfc3339Pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
  if (!rfc3339Pattern.test(deadline)) {
    return `invalid deadline format (expected RFC3339): ${deadline}`;
  }
  const parsed = Date.parse(deadline);
  if (isNaN(parsed)) {
    return `invalid deadline: ${deadline}`;
  }
  if (parsed < Date.now()) {
    return `deadline expired: ${deadline}`;
  }
  return null;
}

// ─── Evidence validation ──────────────────────────────────────────────

/** Pattern for a 64-character lowercase hex SHA-256 digest. */
const HEX_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Validate evidence for CRITICAL operations.
 * CRITICAL success requires:
 *   - evidence.digest matching ^[0-9a-f]{64}$
 *   - evidence.receiptVersion === 3
 *   - execution.runId present
 */
function validateCriticalEvidence(
  outcome: KernelExecutionOutcome,
): string | null {
  if (!outcome.evidence?.digest) {
    return "CRITICAL capability returned SUCCEEDED without evidence digest";
  }
  if (!HEX_DIGEST_PATTERN.test(outcome.evidence.digest)) {
    return `CRITICAL evidence digest is not a valid 64-char lowercase hex SHA-256: ${outcome.evidence.digest}`;
  }
  if (outcome.evidence.receiptVersion !== 3) {
    return `CRITICAL evidence receiptVersion must be 3, got ${outcome.evidence.receiptVersion ?? "missing"}`;
  }
  if (!outcome.execution?.runId) {
    return "CRITICAL capability returned SUCCEEDED without execution.runId";
  }
  return null;
}

// ─── Kernel ───────────────────────────────────────────────────────────

/**
 * Execution adapter routing. PURE capabilities execute locally; all
 * other classes route through the configured execution port.
 */
export interface KernelPorts {
  /** Local execution for PURE capabilities. */
  readonly local: ExecutionPort;
  /** Crabedence (or mock) for READ/MUTATION/CRITICAL. */
  readonly remote: ExecutionPort;
}

/**
 * The NeMo kernel. Routes execution requests based on pinned capability
 * execution classes. Validates schemas, authority references, deadlines,
 * and CRITICAL evidence contracts before accepting outcomes.
 */
export class NemoKernel {
  constructor(
    private readonly catalog: CapabilityCatalog,
    private readonly ports: KernelPorts,
  ) {}

  async execute(
    request: KernelExecutionRequest,
  ): Promise<KernelExecutionOutcome> {
    const descriptor = this.catalog.lookup(request.capabilityId);

    // Enforce execution class immutability.
    if (
      request.executionClass &&
      request.executionClass !== descriptor.executionClass
    ) {
      return {
        status: "DENIED",
        error: `execution class mismatch: requested ${request.executionClass} but capability ${descriptor.id} is pinned as ${descriptor.executionClass}`,
      };
    }

    // Require idempotency keys for mutations.
    if (
      (descriptor.executionClass === "MUTATION" ||
        descriptor.executionClass === "CRITICAL") &&
      !request.idempotencyKey
    ) {
      return {
        status: "DENIED",
        error: `idempotency key required for ${descriptor.executionClass} capabilities`,
      };
    }

    // Validate authority is present and non-empty.
    if (
      !request.authority?.principal ||
      !request.authority?.grantId
    ) {
      return {
        status: "DENIED",
        error: "missing authority principal or grantId",
      };
    }

    // Validate deadline if present.
    const deadlineError = checkDeadline(request.deadline);
    if (deadlineError) {
      return {
        status: "DENIED",
        error: deadlineError,
      };
    }

    // Validate arguments against capability schema.
    const schemaError = validateSchema(request.arguments, descriptor.schema);
    if (schemaError) {
      return {
        status: "DENIED",
        error: `schema validation failed: ${schemaError}`,
      };
    }

    // Route based on execution class.
    const port =
      descriptor.executionClass === "PURE"
        ? this.ports.local
        : this.ports.remote;

    const outcome = await port.execute({
      ...request,
      executionClass: descriptor.executionClass,
    });

    // For CRITICAL operations, verify the evidence contract.
    // A SUCCEEDED CRITICAL must include:
    //   - evidence.digest matching ^[0-9a-f]{64}$
    //   - evidence.receiptVersion === 3
    //   - execution.runId
    if (
      descriptor.executionClass === "CRITICAL" &&
      outcome.status === "SUCCEEDED"
    ) {
      const evidenceError = validateCriticalEvidence(outcome);
      if (evidenceError) {
        return {
          status: "FAILED",
          error: evidenceError,
          execution: outcome.execution,
        };
      }
    }

    return outcome;
  }
}
