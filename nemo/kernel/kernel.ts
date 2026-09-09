/**
 * NeMo kernel — capability catalog and execution routing.
 *
 * The kernel owns:
 *   - capability registration (with pinned execution classes)
 *   - execution class routing (PURE → local, READ/MUTATION/CRITICAL → adapter)
 *   - authority reference forwarding (does not verify authority itself)
 *
 * The kernel does NOT own:
 *   - provider lifecycle
 *   - evidence generation
 *   - receipt signing
 *   - PostgreSQL fencing
 *   - idempotency storage
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
    this.capabilities.set(descriptor.id, Object.freeze({ ...descriptor }));
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
 * execution classes.
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

    // Route based on execution class.
    const port =
      descriptor.executionClass === "PURE"
        ? this.ports.local
        : this.ports.remote;

    return port.execute({
      ...request,
      executionClass: descriptor.executionClass,
    });
  }
}
