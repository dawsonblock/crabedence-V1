import { describe, expect, it } from "vitest";

import {
  actorFromRequest,
  completeBridgePrincipal,
  leaseAccessRoleForPrincipal,
  leaseManagerAuthorized,
  leaseViewerAuthorized,
  normalizedLeaseShare,
  runReadableByPrincipal,
  runReadableToPrincipal,
  runWritableByPrincipal,
} from "../src/authorization";
import { MISSING_ORG_KEY, orgKeyForLabel } from "../src/org-identity";
import type { LeaseRecord, LeaseShare, RunRecord } from "../src/types";

const acme = orgKeyForLabel("acme");
const other = orgKeyForLabel("other");
const legacyOrg = "acme-legacy";

const leaseFixture = (overrides: Partial<LeaseRecord> = {}): LeaseRecord =>
  ({ owner: "alice@example.com", org: acme, ...overrides }) as LeaseRecord;

const runFixture = (overrides: Partial<RunRecord> = {}): RunRecord =>
  ({ owner: "alice@example.com", org: acme, ...overrides }) as RunRecord;

const alice = { owner: "alice@example.com", org: acme, admin: false };
const bob = { owner: "bob@example.com", org: acme, admin: false };

describe("actorFromRequest", () => {
  it("resolves owner, canonical org, label, admin, and auth once", () => {
    const request = new Request("https://example.com/", {
      headers: {
        "x-crabbox-owner": "alice@example.com",
        "x-crabbox-org": "acme",
        "x-crabbox-admin": "true",
        "x-crabbox-auth": "github",
      },
    });
    expect(actorFromRequest(request, { CRABBOX_DEFAULT_ORG: "acme" })).toEqual({
      owner: "alice@example.com",
      org: acme,
      orgLabel: "acme",
      admin: true,
      auth: "github",
    });
  });

  it("falls back to the default org, the unknown owner, and the bearer auth mode", () => {
    const request = new Request("https://example.com/");
    expect(actorFromRequest(request, { CRABBOX_DEFAULT_ORG: "acme" })).toEqual({
      owner: "unknown",
      org: acme,
      orgLabel: "acme",
      admin: false,
      auth: "bearer",
    });
  });

  it("represents a missing org as the missing key and label", () => {
    const actor = actorFromRequest(new Request("https://example.com/"), {});
    expect(actor.org).toBe(MISSING_ORG_KEY);
    expect(actor.orgLabel).toBe("unknown");
  });
});

describe("completeBridgePrincipal", () => {
  it("accepts a complete principal", () => {
    expect(completeBridgePrincipal(alice)).toBe(true);
  });

  it("rejects a principal missing any field", () => {
    expect(completeBridgePrincipal({ owner: "a", org: acme })).toBe(false);
    expect(completeBridgePrincipal({ org: acme, admin: false })).toBe(false);
    expect(completeBridgePrincipal({ owner: "a", admin: false })).toBe(false);
  });

  it("rejects a non-canonical org unless the principal is an admin", () => {
    expect(completeBridgePrincipal({ owner: "a", org: legacyOrg, admin: false })).toBe(false);
    expect(completeBridgePrincipal({ owner: "a", org: legacyOrg, admin: true })).toBe(true);
  });
});

describe("leaseAccessRoleForPrincipal", () => {
  it("gives admins the owner role regardless of scope", () => {
    expect(
      leaseAccessRoleForPrincipal(leaseFixture(), { owner: "x", org: legacyOrg, admin: true }),
    ).toBe("owner");
  });

  it("gives the owner role to the owning principal in the same org", () => {
    expect(leaseAccessRoleForPrincipal(leaseFixture(), alice)).toBe("owner");
  });

  it("does not treat the same owner in another org as the owner", () => {
    expect(leaseAccessRoleForPrincipal(leaseFixture(), { ...alice, org: other })).toBeUndefined();
  });

  it("honours a normalized user share", () => {
    const manage = leaseFixture({
      share: { users: { "Bob@Example.com ": "manage" } } as LeaseShare,
    });
    expect(leaseAccessRoleForPrincipal(manage, bob)).toBe("manage");
    const use = leaseFixture({ share: { users: { "bob@example.com": "use" } } as LeaseShare });
    expect(leaseAccessRoleForPrincipal(use, bob)).toBe("use");
  });

  it("honours an org share only within the same canonical org", () => {
    const lease = leaseFixture({ share: { org: "use" } as LeaseShare });
    expect(leaseAccessRoleForPrincipal(lease, bob)).toBe("use");
    expect(leaseAccessRoleForPrincipal(lease, { ...bob, org: other })).toBeUndefined();
  });

  it("never authorizes a legacy org identity", () => {
    expect(leaseAccessRoleForPrincipal(leaseFixture({ org: legacyOrg }), alice)).toBeUndefined();
    expect(
      leaseAccessRoleForPrincipal(leaseFixture(), { ...alice, org: legacyOrg }),
    ).toBeUndefined();
  });

  it("authorizes the missing-org identity only for the exact same owner", () => {
    const lease = leaseFixture({ org: MISSING_ORG_KEY });
    expect(leaseAccessRoleForPrincipal(lease, { ...alice, org: MISSING_ORG_KEY })).toBe("owner");
    expect(leaseAccessRoleForPrincipal(lease, { ...bob, org: MISSING_ORG_KEY })).toBeUndefined();
  });

  it("does not apply an org share carried by an ambiguous missing-org lease", () => {
    const lease = leaseFixture({
      owner: "someone-else@example.com",
      org: MISSING_ORG_KEY,
      share: { org: "manage" } as LeaseShare,
    });
    expect(leaseAccessRoleForPrincipal(lease, { ...alice, org: MISSING_ORG_KEY })).toBeUndefined();
  });
});

describe("lease manager and viewer authorization", () => {
  it("requires a complete principal", () => {
    expect(leaseManagerAuthorized(leaseFixture(), {})).toBe(false);
    expect(leaseViewerAuthorized(leaseFixture(), { owner: "alice@example.com" })).toBe(false);
  });

  it("grants managers the owner and manage roles, viewers every role", () => {
    expect(leaseManagerAuthorized(leaseFixture(), alice)).toBe(true);
    expect(leaseViewerAuthorized(leaseFixture(), alice)).toBe(true);
    const use = leaseFixture({ share: { users: { "bob@example.com": "use" } } as LeaseShare });
    expect(leaseManagerAuthorized(use, bob)).toBe(false);
    expect(leaseViewerAuthorized(use, bob)).toBe(true);
  });
});

describe("run authorization", () => {
  it("writes only for the owning principal in the same org, or an admin", () => {
    expect(runWritableByPrincipal(runFixture(), alice)).toBe(true);
    expect(runWritableByPrincipal(runFixture(), { ...alice, org: other })).toBe(false);
    expect(runWritableByPrincipal(runFixture(), { owner: "x", org: other, admin: true })).toBe(
      true,
    );
  });

  it("reads for lease owners attributed on the run", () => {
    const run = runFixture({ leaseOwners: [{ owner: "bob@example.com", org: acme }] });
    expect(runReadableByPrincipal(run, bob)).toBe(true);
    expect(runReadableByPrincipal(run, { ...bob, org: other })).toBe(false);
  });

  it("falls back to the lease owner when the run carries no attribution", () => {
    const lease = leaseFixture({ owner: "bob@example.com" });
    const run = runFixture({ owner: "someone-else@example.com" });
    expect(runReadableByPrincipal(run, bob, lease)).toBe(true);
    expect(runReadableByPrincipal(run, { ...bob, org: other }, lease)).toBe(false);
  });

  it("rejects bridge principals whose org is not canonical unless they are admins", () => {
    const run = runFixture({ owner: "bob@example.com" });
    expect(
      runReadableToPrincipal(run, { owner: "bob@example.com", org: legacyOrg, admin: false }),
    ).toBe(false);
    expect(
      runReadableToPrincipal(run, { owner: "bob@example.com", org: legacyOrg, admin: true }),
    ).toBe(true);
    expect(runReadableToPrincipal(run, { owner: "bob@example.com", org: acme, admin: false })).toBe(
      true,
    );
  });

  it("does not read another org's run through an ambiguous legacy attribution", () => {
    const run = runFixture({
      owner: "someone-else@example.com",
      leaseOwners: [{ owner: "bob@example.com", org: legacyOrg }],
    });
    expect(
      runReadableToPrincipal(run, { owner: "bob@example.com", org: legacyOrg, admin: false }),
    ).toBe(false);
  });
});

describe("normalizedLeaseShare", () => {
  it("normalizes users, drops invalid roles, and preserves metadata", () => {
    const share = {
      users: { " Bob@Example.com ": "manage", "": "use", "carol@example.com": "owner" },
      org: "use",
      updatedAt: "2026-01-01T00:00:00Z",
      updatedBy: "alice@example.com",
    } as unknown as LeaseShare;
    expect(normalizedLeaseShare(share)).toEqual({
      users: { "bob@example.com": "manage" },
      org: "use",
      updatedAt: "2026-01-01T00:00:00Z",
      updatedBy: "alice@example.com",
    });
  });

  it("returns an empty share for undefined input", () => {
    expect(normalizedLeaseShare(undefined)).toEqual({ users: {} });
  });
});
