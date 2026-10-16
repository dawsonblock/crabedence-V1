# Unified history and adaptive exploration

Two components turn the system's development record into something it
can learn from:

- `internal/history` — the unified memory: one append-only,
  hash-chained event store ingesting code changes, executions,
  evidence, custody acknowledgements, test results, documents, and
  ad-hoc records.
- `internal/dream` — the replay-and-proposal layer ("Dream-RSI"):
  it fits a parameter model over memory, replays it against the
  record, and proposes execution parameters for new tasks.

## Memory is not authority

The boundary is structural, not procedural:

- Events are records of what already happened. Nothing in `history`
  can sign a contract, emit a receipt, or change a gate.
- `dream.Params` is a resource envelope — `timeout_seconds`,
  `memory_mb`, `cpus`, `disk_mb`, `max_output_bytes` — and nothing
  else. It has no field that can name an authority, a signer, a
  security profile, a network policy, a verification rule, or a
  promotion gate. A test asserts the exact field set; a new field is
  a boundary change that fails the build until a human reviews it.
- The explorer's only output is a `Decision` — an advisory record
  naming one arm of an operator-declared `Envelope`, its estimate,
  and the model digest that produced it. It is not signed and it is
  not a contract: turning it into an execution still requires the
  same signing authority the executor has always demanded. A policy
  that somehow names an arm outside the envelope is refused, and a
  `Decision` whose params do not match its envelope arm is refused
  on record.
- The explorer holds no key material at any point.

## The event store

`history.db` is a SQLite table of events. Every event carries a
kind, subject, correlation key, source, the record's own timestamp,
its canonical JSON payload, and a SHA-256 chain link:

```
sha256 = H(domain ‖ seq ‖ dedupe_key ‖ kind ‖ subject ‖
           correlation ‖ source ‖ occurred_at ‖ payload ‖ prev_sha256)
```

The chain means a rewritten or deleted record is detectable on
`verify`; the `dedupe_key` unique index means every ingest is
idempotent — re-running it appends only what is new. Kinds:
`code_change`, `execution`, `receipt`, `checkpoint`, `custody_ack`,
`test_run`, `test_result`, `document`, `experiment`, `decision`.

## Ingesters

- `ingest-git DIR [range]` — commits as `code_change` events:
  identity, parents, author, message, per-file numstat (renames and
  binary files handled). Dedupes on `git:<repo>:<sha>`.
- `ingest-ledger LEDGER.db` — the executor's job registry (opened
  read-only through `InspectLedger`, no flock contention) as
  `execution` events: state, dispatch class, outcome, and the
  contract's resource/network/security shape parsed from the durable
  contract JSON. Active and archived rows alike; re-ingesting a row
  that settled records the new state — the observation is the
  history.
- `ingest-evidence DIR` — `receipts.jsonl` and `checkpoints/` as
  records that carry what the ingester could verify: intrinsic
  signature validity, trusted-signer membership (from
  `-trusted-signer`), and — when `-ledger` supplies the terminal
  enumeration — full checkpoint verification. A receipt that fails
  intrinsic checks is ingested as a record of failure, not dropped.
- `ingest-custody DIR` — the witness's `acks.jsonl` as `custody_ack`
  events, re-deriving each chain link, each signature under the
  witness domain, and that the segment file named by the digest is
  actually held.
- `ingest-doc FILE...` — documents keyed on content digest, so a
  changed document is a new event and the store keeps the document's
  own history.
- `ingest-teststream FILE` — one `go test -json` stream under the
  canonical per-test lifecycle (`run → (output|pause|cont)* →
  exactly one terminal`), the same rules the release pipeline's
  normalizer enforces. A malformed stream is refused whole — a run
  that cannot be a genuine `go test` output is never normalized into
  plausible-looking history. Emits a `test_run` event keyed on the
  stream's own digest plus one `test_result` per case.
- `append` — ad-hoc records: experiments, failed attempts,
  observations. Dedupes on the content digest unless `-dedupe` is
  given.

## The model

`dream` learns which resource envelope a task family needs:

- An `Envelope` is the operator-declared closed set of arms —
  explicit `Params` points. Nothing outside it can be expressed,
  learned from, or proposed.
- `Reward` = `-1` on failure; `1 − ½·cost` on success, where `cost`
  is the arm's mean per-dimension fraction of the envelope maximum.
  The pressure is "smallest envelope that reliably works".
- `Fit` estimates each arm's expected reward for a task as the
  similarity-weighted mean over that arm's logged outcomes
  (categorical features, similarity⁴), falling back to the arm's
  global mean when similar history is thinner than `minEvidence`.
- `AdaptivePolicy` picks the argmax arm, ties toward the cheaper;
  `StaticPolicy` is the fixed-arm baseline.
- `Replay` scores a policy on the logged record honestly: only
  decisions whose arm history actually ran have a realized outcome
  to score — counterfactual arms are not invented.
- `Benchmark` trains on one window and scores both policies on
  held-out tasks' realized per-arm outcomes — the "gains on unseen
  tasks" evidence.

## Operator flow

```sh
# Build memory
sandbox-history -db history.db ingest-git /repo
sandbox-history -db history.db ingest-ledger executor-ledger.db
sandbox-history -db history.db -ledger executor-ledger.db \
    -trusted-signer <fp> ingest-evidence evidence/
sandbox-history -db history.db -trusted-signer <witness-fp> \
    ingest-custody custody/
sandbox-history -db history.db verify

# Learn and propose
sandbox-dream -db history.db -envelope arms.json report
sandbox-dream -db history.db -envelope arms.json \
    -task-image IMG -task-principal P -task-argv0 A -record propose
sandbox-dream -db history.db -envelope arms.json \
    -holdout holdout.json -baseline N benchmark
```

`arms.json` declares the whole space: `{"arms": [{"timeout_seconds":
..., "memory_mb": ..., "cpus": ..., "disk_mb": ...,
"max_output_bytes": ...}, ...]}`. The holdout file is `[{"task":
{"id","features"}, "arms": [Outcome,...]}]` — realized outcomes per
arm for tasks the fit never saw. `-record` on `propose` appends the
decision itself to memory as a `decision` event, so the explorer's
own proposals become part of the record it learns from.

What the explorer can never do: sign a contract, choose or alter an
authority, pick a security profile or network mode, rewrite a
verification rule, or promote a release. It selects resource
parameters inside an operator-declared envelope, records why, and
nothing it emits carries execution authority.
