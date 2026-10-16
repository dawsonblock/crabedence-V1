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
  contract JSON. Active and archived rows alike. The job's identity
  (subject, contract-hash correlation) is stored apart from each
  observation: dedupe commits to the observation's content, so an
  unchanged re-ingest is idempotent while every material update —
  state transition, receipt binding, archive flip, exit code —
  persists as its own individually identifiable observation.
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
- `ingest-conversations PATH` — development transcripts (Claude Code
  JSONL, generic `role`/`content` rows, JSON arrays) as per-message
  `conversation` events: speaker attribution verbatim, session
  identity, timestamps, tool calls, and touched file paths. Dedupe
  commits to message position + content, so a live transcript's
  appended tail re-ingests incrementally; a line that is not valid
  JSON refuses the ingest.
- `ingest-traces PATH` — agent action traces (JSONL tool-call
  records) as `trace` events: tool, input/output digests, duration,
  run identity. A record naming no tool is refused — it cannot say
  what was done.
- `ingest-archive FILE` — one source archive (zip, tar, tar.gz) as an
  `archive` event: member manifest digest plus detected-vs-supplied
  identity. The project version is detected from `VERSION`,
  `package.json`, or `Cargo.toml` inside the bytes — never the
  filename — and a filename that disagrees with the content records
  `version_conflict`, keeping both claims.
- `ingest-experiments PATH` — JSON experiment records
  (`experiment_id`, `hypothesis`, `arm`, `outcome`, `metrics`) as
  `experiment` events keyed on content; a corrected record is a new
  observation beside the original.
- `ingest-recovery LEDGER.db` — the executor's durable
  `recovery_events` trail (claims, ambiguity markings, expirations,
  escalations) as `recovery` events.

The transcript/trace/archive/experiment ingesters commit source bytes
to a content-addressed `ContentStore` (`<db>.content/objects/<sha256>`,
overridable via `-content-dir`): atomic writes, digest-verified reads,
and `Verify()` reporting objects that fail their own address. Every
event links to the held bytes through `source_sha256`.

## Trust: observations vs. verdicts

The event chain proves its contents were not tampered with. It
cannot by itself prove that its tail is still there, or that a
record in it deserves trust. Two separate mechanisms cover that.

**Witnessed checkpoints.** `sandbox-history -db history.db
checkpoint DIR -witness-key KEY.pem` asks an independent witness —
an Ed25519 key held outside the store — to sign a checkpoint
record: the store's stable `store_id`, the chain's sequence and
head digest, the digest of the applicable source inventory, the
hash of the previous checkpoint (the witnessed series is itself
append-only), and the witness identity. `verify-checkpoint` fetches
the latest checkpoint from outside the database and fails on:

- rollback — events the witness saw are missing below its sequence;
- prefix rewrite — the event at the witnessed sequence no longer
  digests to the witnessed head;
- store replacement — a different (however internally valid)
  database does not inherit the witnessed `store_id`;
- witnessed-series tampering — edited, reordered, or truncated
  checkpoint files break the `previous_checkpoint_hash` links.

A store with more events than the witness saw is progress, not a
finding — checkpoints are historical commitments, and witnessing
proves what was committed, never what was never committed and never
witnessed. Checkpoint files are written atomically (temp, fsync,
rename, directory fsync), so a crash mid-witness leaves the last
committed checkpoint, never a torn one.

**Assessments.** Verdicts about evidence live in a versioned
`assessments` table, apart from the immutable observations they
describe. Each assessment names the observation's dedupe key, the
verifier identity, the verification rules version, a digest of the
trusted-signer set in force, the input digest, and a result:
`VERIFIED`, `REJECTED`, `UNVERIFIED`, `CONFLICTED`, `STALE`.
Ingest emits one per observed receipt, checkpoint, and custody ack;
`EffectiveAssessment` derives the current state for a subject under
a caller-chosen policy:

- no applicable verdict → `UNVERIFIED`;
- latest verdict minted under a different trust set → `STALE` (the
  old verdict stays for audit and never silently upgrades);
- disagreeing verifiers → `CONFLICTED`;
- otherwise the latest applicable verdict.

So re-ingesting a receipt with a newly trusted signer mints a new
`VERIFIED` assessment — the observation is untouched — while a
previously rejected record can never become trusted without a new
assessment explicitly saying so.

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

# Anchor the chain to an independent witness, then check it later
sandbox-history -db history.db checkpoint custody-witnessed/ \
    -witness-key witness-key.pem
sandbox-history -db history.db verify-checkpoint custody-witnessed/ \
    -trusted-signer <witness-fp>

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

## Governed surface (capability registry)

The memory and research operations are registered capabilities, not a
private back channel. The execution service's release registry now
carries eight governed entries, all bound to the `history` adapter:

| Capability | Class | Route | Authority |
|---|---|---|---|
| `history.query` | READ | DIRECT | none |
| `history.verify` | READ | DIRECT | none |
| `history.explain` | READ | DIRECT | none |
| `research.diagnose` | READ | DIRECT | none |
| `research.propose` | READ | DIRECT | none |
| `history.append` | MUTATION | CRABEDENCE | grant required |
| `history.checkpoint` | MUTATION | CRABEDENCE | grant required |
| `research.record_decision` | MUTATION | CRABEDENCE | grant required |

Reads stay observational: they resolve DIRECT and carry no
grant requirement because remembering is not an effect. Writes are
governed effects: appending a record, minting a witness-signed
checkpoint, and recording an explorer decision each route through the
durable execution fabric under an explicit grant, so a memory write is
idempotent, audited, and attributable like any other mutation.

Deployment wiring is `CRABEDENCE_HISTORY_DB` (the store the adapter
serves). Unset, the capabilities stay registered — release policy does
not vary by deployment — and calls fail `CAPABILITY_UNAVAILABLE`, never
`CAPABILITY_NOT_FOUND` and never a silent reroute. The adapter
additionally refuses `history.checkpoint` without
`CRABEDENCE_HISTORY_WITNESS_KEY`: witnessed state is never minted
under an unnamed identity, and the witness lives in deployment
configuration, not in a request an agent could influence.

The advisory boundary is unchanged at the governed layer:
`research.propose` returns interventions inside the caller-declared
envelope — it emits a proposal, not an execution request, and no
capability in this surface can sign a contract, dispatch a job, or
mint evidence.
