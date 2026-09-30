# evidence

`crabbox evidence verify` checks a `RunEvidenceV1` JSON document: it parses
the record with the strict cryptographic-boundary parser (unknown fields,
duplicate keys, trailing data, and incorrect types are all rejected),
validates structural limits, recomputes the SHA-256 digest over the canonical
JSON, and optionally cross-checks a signed v3 terminal run receipt binding.

```sh
crabbox evidence verify evidence.json
crabbox evidence verify evidence.json --receipt receipt.json
```

The command distinguishes three separate trust levels, printed as individual
`PASS` lines:

- `digest=verified` — the recomputed SHA-256 matches the embedded digest.
  This proves integrity only; it does not prove authenticity.
- `receipt_binding=verified` — the supplied receipt is schema version 3 or
  newer and its `evidence_sha256` field equals the evidence digest.
- `receipt_signature=verified` — the receipt's Ed25519 signature verifies
  against its embedded signer key. Only this level establishes authenticity.

A digest alone does not prove authenticity — anyone can compute one. Only a
valid v3 receipt binding plus a verified signature does. Provider
qualification or external authority is out of scope for this command; see
[verify](verify.md) for standalone receipt verification and
[receipt](receipt.md) for producing signed receipts.

On success each check prints a `PASS` line and the command exits 0:

```
PASS evidence.json digest=verified sha256=9f2c...
PASS receipt.json receipt_binding=verified evidence_sha256=9f2c...
PASS receipt.json receipt_signature=verified signer=sha256:6a5f...
```

Any failed check prints a `FAIL` line naming the stage (`parse`,
`structural_validation`, `digest`, `receipt`, `receipt_binding`, or
`receipt_signature`) and exits 1. Unreadable files, malformed arguments, and
receipts below schema version 3 exit 2.
