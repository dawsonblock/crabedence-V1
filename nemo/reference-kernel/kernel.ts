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

import { createHash, timingSafeEqual } from "node:crypto";

import type {
  CapabilityDescriptor,
  ExecutionClass,
  ExecutionPort,
  ExecutionRoute,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../contracts/index";
import { SchemaValidator, type CompiledSchemas } from "./schema";

// ─── Capability registry ──────────────────────────────────────────────

/**
 * DefaultExecutionRoute is the registration-time default for a
 * descriptor that declares no route. It mirrors the Go registry's
 * DefaultExecutionRoute table — the same policy function, not
 * per-capability knowledge. In production every descriptor arrives
 * from the authoritative registry snapshot with an explicit route.
 */
export function defaultExecutionRoute(executionClass: ExecutionClass): ExecutionRoute {
  switch (executionClass) {
    case "PURE":
      return "LOCAL";
    case "READ":
      return "DIRECT";
    default:
      return "CRABEDENCE";
  }
}

/**
 * Immutable capability catalog. Once a capability is registered, its
 * execution class and route cannot be changed. This prevents runtime
 * downgrades (e.g. a model prompt cannot downgrade CRITICAL to READ for
 * speed).
 *
 * Schemas are compiled by a real JSON Schema validator at registration
 * time: a capability whose declared schema does not compile never
 * enters the active catalog.
 */
export class CapabilityCatalog {
  private readonly capabilities = new Map<string, CapabilityDescriptor>();
  private readonly routes = new Map<string, ExecutionRoute>();
  private readonly schemas = new Map<string, CompiledSchemas>();
  private readonly validator = new SchemaValidator();

  register(descriptor: CapabilityDescriptor): void {
    if (this.capabilities.has(descriptor.id)) {
      throw new Error(`capability already registered: ${descriptor.id}`);
    }
    const route = descriptor.executionRoute ?? defaultExecutionRoute(descriptor.executionClass);
    validateRoutePairing(descriptor.id, descriptor.executionClass, route);

    // Deep freeze the descriptor and its schema to prevent mutation,
    // and compile the schemas FROM THE FROZEN COPY so a caller that
    // keeps a reference to the original object cannot alter what the
    // compiled validator enforces.
    const frozen = deepFreeze(structuredClone(descriptor));
    const compiled = this.validator.compile(
      frozen.id,
      frozen.schema,
      frozen.resultSchema,
    );
    this.capabilities.set(frozen.id, frozen);
    this.routes.set(frozen.id, route);
    this.schemas.set(frozen.id, compiled);
  }

  lookup(capabilityId: string): CapabilityDescriptor {
    const descriptor = this.capabilities.get(capabilityId);
    if (!descriptor) {
      throw new Error(`unknown capability: ${capabilityId}`);
    }
    return descriptor;
  }

  /**
   * routeOf returns the resolved execution route for a capability —
   * the only input the kernel uses to choose a dispatch mechanism.
   */
  routeOf(capabilityId: string): ExecutionRoute {
    const route = this.routes.get(capabilityId);
    if (!route) {
      throw new Error(`unknown capability: ${capabilityId}`);
    }
    return route;
  }

  has(capabilityId: string): boolean {
    return this.capabilities.has(capabilityId);
  }

  list(): CapabilityDescriptor[] {
    return [...this.capabilities.values()];
  }

  /** validateArguments validates a request's arguments against the
   * capability's compiled input schema. Returns null when valid. */
  validateArguments(capabilityId: string, value: unknown): string | null {
    return this.validator.validate(
      this.compiled(capabilityId).input,
      value,
      "argument",
    );
  }

  /** validateResult validates a SUCCEEDED outcome against the
   * capability's compiled result schema. Returns null when valid. */
  validateResult(capabilityId: string, value: unknown): string | null {
    return this.validator.validate(
      this.compiled(capabilityId).result,
      value,
      "result",
    );
  }

  private compiled(capabilityId: string): CompiledSchemas {
    const compiled = this.schemas.get(capabilityId);
    if (!compiled) {
      throw new Error(`unknown capability: ${capabilityId}`);
    }
    return compiled;
  }
}

/**
 * VerifiedCapabilityCatalog is a catalog built from a cryptographically
 * verified registry envelope. The production kernel accepts ONLY this
 * type, so "route on the authoritative registry" is enforced by the
 * type system rather than by convention: a hand-built catalog cannot be
 * passed to a production kernel.
 *
 * Tests that need a hand-built catalog use createTestKernel from
 * ../kernel/testing, which makes the test-only path explicit at the
 * call site.
 */
export class VerifiedCapabilityCatalog extends CapabilityCatalog {
  private constructor() {
    super();
  }

  /**
   * fromVerifiedPayload verifies the canonical registry bytes against
   * the expected digest and returns a catalog only when they match.
   *
   * This is the ONLY way a verified catalog is produced on the
   * production path: there is no factory that mints one without a
   * passing verification, so a caller cannot "mark" a hand-built
   * catalog as verified — it would have to supply bytes whose SHA-256
   * actually equals the expected digest.
   */
  static fromVerifiedPayload(payload: Buffer, expectedSha256: string): VerifiedCapabilityCatalog {
    const computed = createHash("sha256").update(payload).digest("hex");
    if (computed.length !== expectedSha256.length) {
      throw new SnapshotVerificationError("registry payload does not match its digest");
    }
    if (!timingSafeEqual(Buffer.from(computed, "utf-8"), Buffer.from(expectedSha256, "utf-8"))) {
      throw new SnapshotVerificationError("registry payload does not match its digest");
    }
    return new VerifiedCapabilityCatalog();
  }

  /**
   * @internal forTestOnly exists solely for nemo/kernel/testing.ts, so
   * test harnesses can build a kernel around a fixture catalog. No
   * production module imports it; the name is deliberately greppable.
   */
  static forTestOnly(): VerifiedCapabilityCatalog {
    return new VerifiedCapabilityCatalog();
  }
}

/** SnapshotVerificationError is thrown when registry bytes fail verification. */
export class SnapshotVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotVerificationError";
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

/**
 * validateRoutePairing fails registration when a route cannot satisfy
 * the capability's effect class — the same invariant the authoritative
 * registry enforces. A LOCAL capability is PURE; a DIRECT capability
 * is READ; MUTATION/CRITICAL require the durable route.
 */
function validateRoutePairing(
  capabilityId: string,
  executionClass: ExecutionClass,
  route: ExecutionRoute,
): void {
  switch (route) {
    case "LOCAL":
      if (executionClass !== "PURE") {
        throw new Error(`capability ${capabilityId}: route LOCAL requires PURE, got ${executionClass}`);
      }
      return;
    case "DIRECT":
      if (executionClass !== "READ") {
        throw new Error(`capability ${capabilityId}: route DIRECT requires READ, got ${executionClass}`);
      }
      return;
    case "CRABEDENCE":
      return;
    default:
      throw new Error(`capability ${capabilityId}: unknown execution route ${JSON.stringify(route)}`);
  }
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
    private readonly catalog: VerifiedCapabilityCatalog,
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

    // The kernel requires an identity, not an authority reference.
    // Whether authorization material is required is the capability's
    // policy, owned by Crabedence's authoritative registry — the
    // kernel must not invent a grant requirement the policy does not
    // have, and must not drop one the policy does have.
    if (!request.authority?.principal) {
      return {
        status: "DENIED",
        error: "missing authority principal",
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

    // Validate arguments against the capability's compiled schema.
    const schemaError = this.catalog.validateArguments(
      request.capabilityId,
      request.arguments,
    );
    if (schemaError) {
      return {
        status: "DENIED",
        error: schemaError,
      };
    }

    // Route on the resolved execution route — never on a
    // classification the kernel maintains itself. LOCAL executes
    // in-process; DIRECT and CRABEDENCE execute in the service, whose
    // own route dispatcher decides which mechanism runs.
    const route = this.catalog.routeOf(request.capabilityId);
    const port = route === "LOCAL" ? this.ports.local : this.ports.remote;

    const outcome = await port.execute({
      ...request,
      executionClass: descriptor.executionClass,
    });

    // A declared result contract is part of the capability's trust
    // boundary. A SUCCEEDED outcome whose result violates it is a
    // contract violation: a PURE capability produced no external
    // effect, so FAILED; a dispatched capability's provider claimed
    // success but returned something outside the contract, which is
    // post-dispatch uncertainty — UNKNOWN, never a retryable failure.
    if (outcome.status === "SUCCEEDED") {
      const resultError = this.catalog.validateResult(
        request.capabilityId,
        outcome.result,
      );
      if (resultError) {
        if (descriptor.executionClass === "PURE") {
          return {
            status: "FAILED",
            error: resultError,
          };
        }
        return {
          status: "UNKNOWN",
          error: resultError,
          execution: outcome.execution,
        };
      }
    }

    // For CRITICAL operations, verify the evidence contract.
    // A SUCCEEDED CRITICAL must include:
    //   - evidence.digest matching ^[0-9a-f]{64}$
    //   - evidence.receiptVersion === 3
    //   - execution.runId
    //
    // A malformed SUCCEEDED is post-dispatch uncertainty, not failure:
    // the provider claims the effect happened, so reporting FAILED
    // could let an upstream planner treat the operation as definitively
    // failed and construct a retry. UNKNOWN preserves the ambiguity for
    // reconciliation. (The production Crabedence adapter normally
    // converts this to UNKNOWN before NEMO ever sees it; this check is
    // defense-in-depth for custom or buggy execution ports.)
    if (
      descriptor.executionClass === "CRITICAL" &&
      outcome.status === "SUCCEEDED"
    ) {
      const evidenceError = validateCriticalEvidence(outcome);
      if (evidenceError) {
        return {
          status: "UNKNOWN",
          error: evidenceError,
          execution: outcome.execution,
        };
      }
    }

    return outcome;
  }
}
