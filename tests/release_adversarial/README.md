# Release-adversarial corpus (RC7.5)

The adversarial release cases are generated programmatically by
`scripts/verify-rc75-release.test.py` rather than stored as binary
fixtures — an archive checked in as a fixture could itself drift from
what the description claims it contains. The builder is the fixture:
each case is deterministic, and the test asserts the exact refusal.

| Case | Attack | Expected refusal |
|------|--------|------------------|
| Archive substitution | Different bytes under the qualified name | `archive SHA-256 does not match the attestation` |
| Tampered member | One byte changed inside the archive | `content hash mismatch` (under a forged attestation) |
| Path traversal | Member escaping the extraction root | `unsafe archive member` |
| Container symlink | Real zip symlink entry | `archive member is a symlink` |
| Missing member | Manifest entry absent from archive | `manifest entry missing from tree` |
| Extra member | Unpackaged file inside the archive | `unpackaged file in tree` |
| Forged attestation | Attestation recomputed over attacker bytes / wrong version | version binding + retained-manifest checks refuse it |
| Version drift | VERSION declares a different release | `VERSION declares …` |
| Missing lockfile | `go.mod`/`go.sum` dropped | `dependency lock missing` |
| Manifest recursion | Attestation listed inside the manifest | generator refuses to emit it |
| Clean package | Control case | verifies |

Run: `python3 scripts/verify-rc75-release.test.py`
