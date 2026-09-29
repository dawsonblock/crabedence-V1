# Coordinator Scaling

The Cloudflare Worker coordinator routes every request to a single
Durable Object: `env.FLEET.idFromName("default")`. This document
records why that is the current design, what it bounds, and what a
sharded topology would have to preserve.

## Why a single Durable Object

The Fleet object is the coordinator's single-writer consistency point.
Lease claiming, idempotent provisioning, and checkpoint shard claims
all rely on one serialized log of mutations:

- A lease has exactly one owner. Claim, renew, and release are
  compare-and-set transitions against state the DO serializes; there is
  no cross-object lock.
- Provider effects are idempotent per lease. The coordinator mints
  effect identities that must be unique cluster-wide, which is trivial
  under a single writer and becomes a distributed-allocation problem
  under many.
- Checkpoint shard claims are owner-scoped the same way (see
  [coordinator.md](../features/coordinator.md)).

Durable Object request handling is single-threaded per object and
input-gated, so the object is also the natural place for the
coordinator's ordering guarantees. Nothing in the current design
tolerates two independent writers for the same lease or the same
idempotency key.

## What the single object bounds

- Throughput scales with one object's serialized request execution, not
  with the number of Worker isolates. Read-heavy routes (status, list)
  still pay the serialization.
- Availability is the object's availability: a hot or wedged object
  delays every tenant.
- Blast radius is total: all state and all tenants share one object's
  storage and alarms.

These are acceptable for the current scale and are the price of the
consistency properties above. They are not acceptable as an
indefinite ceiling.

## What sharding would require

A sharded coordinator is a correctness change, not a routing change.
Any proposal must answer, in order:

1. **Partition key.** The only candidates are keys whose invariants
   never span partitions: org, or repo. Lease IDs, slugs, and
   principals cannot be keys unless the invariants above are relaxed.
2. **Cross-partition identity allocation.** Effect identities that must
   be unique per tenant need either partition-scoped namespaces (key
   embedded in the identity) or a separate allocator object.
3. **Migration.** Durable Object storage cannot be split in place; a
   sharded rollout needs a dual-write or export/import path with a
   freeze window, and the freeze must itself be coordinated by the
   object being split.
4. **Routing.** The Worker must derive the partition from the request
   before any state read, including for admin and scheduled routes,
   which today assume the single object.

Until those answers exist as a reviewed design, the single object stays
the coordinator's consistency boundary. Scaling pressure should first
be met by making read-heavy routes cheaper (caching projections in the
Worker, `ctx.waitUntil` for telemetry) rather than by splitting state.
