import { describe, expect, it } from "vitest";

import type { LeaseConfig } from "../src/config";
import {
  LEASE_STATES,
  clearProvisioningRecoveryMetadata,
  finalizedReleasedLease,
  isRegisteredLease,
  isTerminalLeaseState,
  leaseCleanupIsUnresolved,
  leaseHeartbeatStateError,
  leaseIsLive,
  provisionedLeaseRecord,
  retainUnresolvedProviderResource,
  terminalizeManualProviderCleanup,
} from "../src/lease-lifecycle";
import { orgKeyForLabel } from "../src/org-identity";
import { providerKeyForLease } from "../src/provider-key";
import type { LeaseRecord, ProviderMachine } from "../src/types";

const acme = orgKeyForLabel("acme");

const leaseFixture = (overrides: Partial<LeaseRecord> = {}): LeaseRecord =>
  ({
    id: "lease-1",
    provider: "hetzner",
    cloudID: "srv-1",
    serverID: "1",
    serverName: "srv-1",
    serverType: "cx22",
    providerKey: "cbx-key",
    owner: "alice@example.com",
    org: acme,
    state: "active",
    lifecycle: "managed",
    createdAt: "2026-09-24T00:00:00.000Z",
    updatedAt: "2026-09-24T00:00:00.000Z",
    expiresAt: "2026-09-24T02:00:00.000Z",
    ...overrides,
  }) as LeaseRecord;

const configFixture = (overrides: Partial<LeaseConfig> = {}): LeaseConfig =>
  ({
    provider: "hetzner",
    providerKey: "cbx-key",
    ...overrides,
  }) as LeaseConfig;

const serverFixture = (overrides: Partial<ProviderMachine> = {}): ProviderMachine =>
  ({
    provider: "hetzner",
    id: 1,
    cloudID: "srv-1",
    name: "srv-1",
    status: "running",
    serverType: "cx22",
    host: "1.2.3.4",
    ...overrides,
  }) as ProviderMachine;

describe("lease state predicates", () => {
  it("classifies every state as live or terminal exactly once", () => {
    const rows = LEASE_STATES.map((state) => ({
      state,
      live: leaseIsLive(leaseFixture({ state })),
      terminal: isTerminalLeaseState(state),
    }));
    expect(rows).toEqual([
      { state: "provisioning", live: true, terminal: false },
      { state: "active", live: true, terminal: false },
      { state: "released", live: false, terminal: true },
      { state: "expired", live: false, terminal: true },
      { state: "failed", live: false, terminal: true },
    ]);
  });

  it("recognizes registered leases", () => {
    expect(isRegisteredLease(leaseFixture({ lifecycle: "registered" }))).toBe(true);
    expect(isRegisteredLease(leaseFixture())).toBe(false);
  });

  it("reports unresolved cleanup only for explicit, unretryable debt", () => {
    const unresolved = leaseFixture({
      state: "failed",
      provisioningResourceMayExist: true,
      provisioningFailureRetryable: false,
      failureError: "unresolved",
      cleanupError: "unresolved",
    });
    expect(leaseCleanupIsUnresolved(unresolved)).toBe(true);
    expect(
      leaseCleanupIsUnresolved(
        leaseFixture({
          ...unresolved,
          cleanupRetryAt: "2026-09-24T01:00:00.000Z",
        } as Partial<LeaseRecord>),
      ),
    ).toBe(false);
    expect(
      leaseCleanupIsUnresolved(
        leaseFixture({ ...unresolved, provisioningFailureRetryable: true } as Partial<LeaseRecord>),
      ),
    ).toBe(false);
    expect(leaseCleanupIsUnresolved(leaseFixture())).toBe(false);
  });
});

describe("lease heartbeat", () => {
  const now = Date.parse("2026-09-24T01:00:00.000Z");

  it("refuses a heartbeat on a terminal lease", () => {
    for (const state of ["released", "expired", "failed"] as const) {
      expect(leaseHeartbeatStateError(leaseFixture({ state }), now)).toBe("lease_ended");
    }
  });

  it("refuses a heartbeat past the expiry, including a malformed expiry", () => {
    expect(leaseHeartbeatStateError(leaseFixture(), now)).toBeUndefined();
    expect(
      leaseHeartbeatStateError(leaseFixture({ expiresAt: "2026-09-24T00:30:00.000Z" }), now),
    ).toBe("lease_expired");
    expect(leaseHeartbeatStateError(leaseFixture({ expiresAt: "not-a-date" }), now)).toBe(
      "lease_expired",
    );
  });
});

describe("activation", () => {
  it("binds the provider instance and preserves the create-attempt identity", () => {
    const lease = leaseFixture({
      state: "provisioning",
      cloudID: "",
      serverID: undefined,
      createAttemptID: "attempt-1",
      createAttemptGeneration: "gen-7",
    } as Partial<LeaseRecord>);
    const activated = provisionedLeaseRecord(
      lease,
      configFixture(),
      serverFixture({ providerResourceID: "res-9", hostID: "host-3" }),
      "cx22",
    );
    expect(activated.state).toBe("active");
    expect(activated.cloudID).toBe("srv-1");
    expect(activated.serverID).toBe(1);
    expect(activated.serverName).toBe("srv-1");
    expect(activated.host).toBe("1.2.3.4");
    expect(activated.providerResourceID).toBe("res-9");
    expect(activated.hostId).toBe("host-3");
    // The generation that authorized the attempt survives activation: a
    // (leaseId, generation) identity is never reduced to leaseId.
    expect(activated.createAttemptGeneration).toBe("gen-7");
    expect(activated.createAttemptID).toBe("attempt-1");
  });

  it("only claims provider-key cleanup ownership for its own key", () => {
    const owned = provisionedLeaseRecord(
      leaseFixture({ state: "provisioning" }),
      configFixture({ providerKey: providerKeyForLease("lease-1") }),
      serverFixture(),
      "cx22",
    );
    expect(owned.providerKeyCleanupOwned).toBe(true);
    const foreign = provisionedLeaseRecord(
      leaseFixture({ state: "provisioning" }),
      configFixture({ providerKey: "someone-elses-key" }),
      serverFixture(),
      "cx22",
    );
    expect(foreign.providerKeyCleanupOwned).toBe(false);
  });
});

describe("failure never masquerades as absence", () => {
  it("marks a live lease failed and keeps the unresolved resource as explicit debt", () => {
    const lease = leaseFixture({ state: "provisioning", cloudID: "" } as Partial<LeaseRecord>);
    retainUnresolvedProviderResource(lease, "resource may exist", "2026-09-24T01:00:00.000Z");
    expect(lease.state).toBe("failed");
    expect(lease.endedAt).toBe("2026-09-24T01:00:00.000Z");
    expect(lease.provisioningResourceMayExist).toBe(true);
    expect(lease.provisioningFailureRetryable).toBe(false);
    expect(lease.cleanupRetryAt).toBeUndefined();
    expect(lease.cleanupError).toBe("resource may exist");
    expect(leaseCleanupIsUnresolved(lease)).toBe(true);
  });

  it("records the debt without resurrecting a terminal lease", () => {
    const lease = leaseFixture({ state: "released" });
    retainUnresolvedProviderResource(lease, "resource may exist", "2026-09-24T01:00:00.000Z");
    expect(lease.state).toBe("released");
    expect(lease.provisioningResourceMayExist).toBe(true);
  });
});

describe("release", () => {
  it("records release intent for a provisioned lease", () => {
    const released = finalizedReleasedLease(leaseFixture(), true);
    expect(released.state).toBe("released");
    expect(released.releasedAt).toBeDefined();
    expect(released.endedAt).toBe(released.releasedAt);
    expect(released.releaseDeletesServer).toBeUndefined();
  });

  it("keeps the recovery evidence when the creation is unresolved", () => {
    const unresolved = leaseFixture({
      state: "provisioning",
      cloudID: "",
      provisioningRequestStartedAt: "2026-09-24T00:10:00.000Z",
    } as Partial<LeaseRecord>);
    const released = finalizedReleasedLease(unresolved, true);
    expect(released.state).toBe("released");
    expect(released.provisioningResourceMayExist).toBe(true);
    expect(released.cleanupError).toBe(
      "provider creation is unresolved; cleanup has not been confirmed",
    );
    expect(released.releaseDeletesServer).toBe(true);
  });

  it("is idempotent in state and flags", () => {
    const once = finalizedReleasedLease(leaseFixture(), false);
    const twice = finalizedReleasedLease(once, false);
    expect(twice.state).toBe("released");
    expect(twice.releaseDeletesServer).toBe(once.releaseDeletesServer);
    expect(twice.keep).toBe(once.keep);
    expect(twice.releasedAt).toBeDefined();
  });
});

describe("terminal expiry for manual cleanup", () => {
  it("expires a live lease, disclaims deletion, and clears every retry marker", () => {
    const lease = leaseFixture({
      state: "active",
      cleanupAttempts: 3,
      cleanupError: "manual",
      cleanupFailedAt: "2026-09-24T00:30:00.000Z",
      cleanupRetryAt: "2026-09-24T01:30:00.000Z",
      cleanupStartedAt: "2026-09-24T00:40:00.000Z",
      cleanupClaimExpiresAt: "2026-09-24T00:50:00.000Z",
      provisioningResourceMayExist: true,
      provisioningFailureRetryable: true,
    } as Partial<LeaseRecord>);
    terminalizeManualProviderCleanup(lease, "needs a human", "2026-09-24T02:00:00.000Z");
    expect(lease.state).toBe("expired");
    expect(lease.keep).toBe(true);
    expect(lease.releaseDeletesServer).toBe(false);
    expect(lease.failureError).toBe("needs a human");
    expect(lease.cleanupAttempts).toBeUndefined();
    expect(lease.cleanupRetryAt).toBeUndefined();
    expect(lease.cleanupStartedAt).toBeUndefined();
    expect(lease.cleanupClaimExpiresAt).toBeUndefined();
    expect(lease.provisioningResourceMayExist).toBeUndefined();
  });

  it("does not change the state of a terminal lease", () => {
    const lease = leaseFixture({ state: "released" });
    terminalizeManualProviderCleanup(lease, "needs a human", "2026-09-24T02:00:00.000Z");
    expect(lease.state).toBe("released");
    expect(lease.keep).toBe(true);
  });
});

describe("provisioning recovery metadata", () => {
  it("clears the recovery markers and resets the uncertainty flags", () => {
    const lease = leaseFixture({
      provisioningRequestStartedAt: "2026-09-24T00:10:00.000Z",
      provisioningCoordinatorVersion: "v1",
      provisioningRequestSettledAt: "2026-09-24T00:11:00.000Z",
      provisioningRecoveryObservedAt: "2026-09-24T00:12:00.000Z",
      provisioningRecoveryMissingSince: "2026-09-24T00:13:00.000Z",
      provisioningResourceMayExist: true,
      provisioningFailureRetryable: true,
    } as Partial<LeaseRecord>);
    clearProvisioningRecoveryMetadata(lease);
    expect(lease.provisioningRequestStartedAt).toBeUndefined();
    expect(lease.provisioningCoordinatorVersion).toBeUndefined();
    expect(lease.provisioningRequestSettledAt).toBeUndefined();
    expect(lease.provisioningRecoveryObservedAt).toBeUndefined();
    expect(lease.provisioningRecoveryMissingSince).toBeUndefined();
    expect(lease.provisioningResourceMayExist).toBe(false);
    expect(lease.provisioningFailureRetryable).toBe(false);
  });
});
