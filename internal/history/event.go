// Package history is the unified memory layer: an append-only,
// hash-chained event store that ingests the system's whole
// development record — code changes, executions, evidence, custody,
// test results, and documents — into one queryable, verifiable
// history.
//
// Memory is not authority. Nothing in this package can sign a
// contract, emit a receipt, or alter a gate: events are records of
// what already happened, chained so their tampering is detectable,
// so downstream learning (internal/dream) trains on the record the
// system actually produced — not a rewritten one.
package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// digestDomain separates history-event digests from every other
// SHA-256 construction in the system — an event digest can never
// collide with a contract hash, a receipt digest, or a custody ack
// under a different interpretation.
const digestDomain = "crabedence.history-event.v1\x00"

// genesisPrev is the prev_sha256 the first event links to. A chain
// that does not begin here was not built by this store.
const genesisPrev = "GENESIS"

// Event kinds. The set is deliberately open — new record families
// extend it — but each ingester writes exactly one, so a query by
// kind always sees a single ingest path's records.
const (
	// KindCodeChange is one git commit: what changed, when, and how
	// much — the development timeline.
	KindCodeChange = "code_change"
	// KindExecution is one executor job's durable registry record
	// (active or archived): what ran, under what contract, with what
	// outcome.
	KindExecution = "execution"
	// KindReceipt is one signed terminal evidence receipt.
	KindReceipt = "receipt"
	// KindCheckpoint is one signed evidence checkpoint.
	KindCheckpoint = "checkpoint"
	// KindCustodyAck is one external-custody acknowledgement.
	KindCustodyAck = "custody_ack"
	// KindTestRun is one normalized `go test -json` run.
	KindTestRun = "test_run"
	// KindTestResult is one test case inside a normalized run.
	KindTestResult = "test_result"
	// KindDocument is one ingested document at a digest — research,
	// design notes, reports. Re-ingesting a changed document is a
	// new event, so the store keeps the document's own history.
	KindDocument = "document"
	// KindExperiment is an ad-hoc record — an experiment, a failed
	// attempt, an observation — appended through Append directly.
	KindExperiment = "experiment"
	// KindDecision is an explorer's advisory parameter choice for a
	// task: the adaptive controller's own learning record, so its
	// proposals are themselves part of history.
	KindDecision = "decision"
)

// Event is one appended record. The identity fields live in columns;
// the payload is the canonical JSON record as ingested.
type Event struct {
	Seq         int64
	DedupeKey   string
	Kind        string
	Subject     string
	Correlation string
	Source      string
	// OccurredAt is the event's own time (commit time, job receipt
	// time, document mtime) in unix milliseconds — not the time it
	// was ingested. The chain order, not this field, is canonical.
	OccurredAt int64
	Payload    json.RawMessage
	SHA256     string
	PrevSHA256 string
}

// digest computes the event's chain link over its full identity and
// payload — the same length-prefixed, domain-separated construction
// as contracts and receipts, so a digest means exactly one byte
// string under exactly one interpretation.
func digest(seq int64, dedupeKey, kind, subject, correlation, source string, occurredAt int64, payload []byte, prevSHA256 string) string {
	var b bytes.Buffer
	b.WriteString(digestDomain)
	var l [4]byte
	put := func(s string) {
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b.Write(l[:])
		b.WriteString(s)
	}
	putb := func(p []byte) {
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	putInt := func(v int64) {
		var i [8]byte
		binary.BigEndian.PutUint64(i[:], uint64(v))
		b.Write(i[:])
	}
	putInt(seq)
	put(dedupeKey)
	put(kind)
	put(subject)
	put(correlation)
	put(source)
	putInt(occurredAt)
	putb(payload)
	put(prevSHA256)
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// validate checks the fields the store's integrity requires before
// the digest is even computed — a malformed event is refused, never
// normalized.
func (e *Event) validate() error {
	if e == nil {
		return fmt.Errorf("missing event")
	}
	if e.DedupeKey == "" {
		return fmt.Errorf("event dedupe key is required")
	}
	if e.Kind == "" {
		return fmt.Errorf("event kind is required")
	}
	if e.Subject == "" {
		return fmt.Errorf("event subject is required")
	}
	if e.Source == "" {
		return fmt.Errorf("event source is required")
	}
	if len(e.Payload) == 0 {
		return fmt.Errorf("event payload is required")
	}
	if !json.Valid(e.Payload) {
		return fmt.Errorf("event payload is not valid JSON")
	}
	return nil
}
