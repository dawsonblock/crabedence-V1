# RC7.5 Security Review

Self-review of the RC7.5 hardening against its own invariants — where
each control is complete, where it is compensating rather than native,
and what remains honestly open.

## Verdict per invariant

| Invariant | Status | Basis |
|---|---|---|
| INV-01 identity-safe destruction | **Implemented, compensating** | Identity-bound `CleanupRequest`/`CleanupResult`, label-conditioned `msb rm`, pre/post verification. *Compensating* because msb's CLI exposes no documented atomic conditional-delete — see T1 residual. |
| INV-02 ambiguous effects | Implemented | Ambiguous dispatch is durable state, reconciled not replayed; admission claims intent atomically. |
| INV-03 recovery ownership | Implemented | Full claim (job/action/attempt/epoch/`claim_uid`/lease) validated in the same transaction as every protected write; generations never reused. |
| INV-04 fenced external operations | **Implemented at commit boundary** | Claim re-validated at commit; `RecoveryFence` carried to the backend. Backend-side enforcement is limited to label conditioning (T4 residual) — the fence is presented, not natively enforced by msb. |
| INV-05 evidence integrity | Implemented; custody **pending** | Hash chain + signed checkpoints + durable outbox + competing-head detection all landed and tested. External custody integration **not yet exercised against a real independent destination** — the one honest gap. |
| INV-06 evidence authenticity | Implemented | Strict stream validation (16 fixtures) + explicit structural/provenance separation. |
| INV-07 release binding | Implemented | Canonical manifest + sidecar attestation + fresh-extraction verifier + 11 adversarial cases. |

## Deliberate non-claims

- `msb rm --label` is **not** represented as an atomic
  conditional-delete: it is a conditioned remove bounded by msb's
  transition guard, plus independent verification. The plan's own
  rule — "do not substitute inspect-then-delete as proof of
  atomicity" — is honored by *not claiming* atomicity and by failing
  closed to `REMOVAL_UNCERTAIN` on unresolved windows.
- The `SocketCustodian` recovery witness is wired but its independent
  custody lane is `NOT_RUN`; `PARTIAL` in the matrix is honest, not
  decorative.
- Pre-v12 recovery rows are `authenticated = 0` forever — the chain
  binds them for tamper-evidence but they are never retroactively
  called signed history.

## Fail-closed audit

Every new boundary fails closed, checked path by path:

- Empty/wildcard identity fields → `Validate()` refusal, never a match-all.
- Cleanup outcomes other than `ProvesAbsent()` → pending stays set.
- Stale claim at any protected boundary → `ErrClaimStale`, write refused.
- Evidence write failure → the guarded state change rolls back with it.
- Custody ack failing verification or regressing sequence → escalated
  and left pending, never recorded.
- Archive verification failure → `verify` exits non-zero; nothing is
  "probably fine."
