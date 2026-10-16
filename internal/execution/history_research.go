package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/experience"
	"github.com/openclaw/crabbox/internal/history"
	"github.com/openclaw/crabbox/internal/research"
)

// The NEMO governed memory surface: history.* reads and appends,
// research.* advisory computations. READ capabilities resolve to the
// DIRECT route — observational, audited, outside the durable mutation
// ledger. MUTATION capabilities (history.append,
// research.record_decision, history.checkpoint) go through the
// CRABEDENCE route under grant control — writing memory is a real
// effect, and witnessed state is minted nowhere else.
//
// The adapter is deployment wiring: registered unconditionally (the
// release's policy surface) and served only when CRABEDENCE_HISTORY_DB
// names a store, else the calls fail CAPABILITY_UNAVAILABLE — never
// CAPABILITY_NOT_FOUND.

const historyAdapterID = "history"

// HistoryAdapter serves the governed memory surface against one
// history store. The store handle is write-capable — mutation
// capabilities flow through the durable executor, whose idempotency
// ledger makes a retried call land exactly once regardless of what
// the event dedupe keys do.
type HistoryAdapter struct {
	store      *history.Store
	witnessKey string
	contentDir string
}

// NewHistoryAdapter opens the configured store for the governed
// surface. witnessKey, when set, enables history.checkpoint — the
// witness is a key outside the store's administrative control.
// contentDir defaults to the store's sibling object dir.
func NewHistoryAdapter(dbPath, witnessKey, contentDir string) (*HistoryAdapter, error) {
	s, err := history.OpenStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("history adapter open %s: %w", dbPath, err)
	}
	if contentDir == "" {
		contentDir = dbPath + ".content"
	}
	return &HistoryAdapter{store: s, witnessKey: witnessKey, contentDir: contentDir}, nil
}

// Close releases the store handle.
func (a *HistoryAdapter) Close() error { return a.store.Close() }

// Execute dispatches one admitted call by capability.
func (a *HistoryAdapter) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	runID := fmt.Sprintf("history-%d", time.Now().UnixNano())
	var result json.RawMessage
	var err error
	switch req.Capability {
	case "history.query":
		result, err = a.doQuery(req.Arguments)
	case "history.verify":
		result, err = a.doVerify()
	case "history.explain":
		result, err = a.doExplain(req.Arguments)
	case "research.diagnose":
		result, err = a.doDiagnose()
	case "research.propose":
		result, err = a.doPropose(req.Arguments)
	case "history.append":
		result, err = a.doAppend(req.Arguments)
	case "research.record_decision":
		result, err = a.doRecordDecision(req.Arguments)
	case "history.checkpoint":
		result, err = a.doCheckpoint(req.Arguments)
	default:
		err = fmt.Errorf("unknown governed memory capability %s", req.Capability)
	}
	if err != nil {
		return Response{Status: StatusFailed, Error: err.Error(), DefinitiveFailure: true}
	}
	return Response{
		Status: StatusSucceeded,
		Result: result,
		Execution: &ExecutionMeta{
			Provider: historyAdapterID,
			RunID:    runID,
		},
	}
}

// doQuery answers history.query: events matching the caller's filters.
func (a *HistoryAdapter) doQuery(args json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Kinds       []string `json:"kinds"`
		Subject     string   `json:"subject"`
		Correlation string   `json:"correlation"`
		Since       int64    `json:"since"`
		Until       int64    `json:"until"`
		Limit       int      `json:"limit"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &q); err != nil {
			return nil, fmt.Errorf("history.query arguments: %w", err)
		}
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	events, err := a.store.Query(history.QueryOpts{
		Kinds: q.Kinds, Subject: q.Subject, Correlation: q.Correlation,
		Since: q.Since, Until: q.Until, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"events": events, "count": len(events)})
}

// doVerify re-derives the chain and reports stats — the memory's own
// integrity check, answerable without any witness.
func (a *HistoryAdapter) doVerify() (json.RawMessage, error) {
	findings := a.store.Verify()
	total, perKind, head, err := a.store.Stats()
	if err != nil {
		return nil, err
	}
	id, _ := a.store.StoreID()
	return json.Marshal(map[string]any{
		"ok":       len(findings) == 0,
		"findings": findings,
		"events":   total,
		"per_kind": perKind,
		"head":     head,
		"store_id": id,
	})
}

// doExplain reconstructs the experience and renders one node's
// position — the governed way an agent asks "what happened here".
func (a *HistoryAdapter) doExplain(args json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Node string `json:"node"`
	}
	if err := json.Unmarshal(args, &q); err != nil || q.Node == "" {
		return nil, fmt.Errorf("history.explain requires node")
	}
	g, err := experience.Reconstruct(a.store, "")
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"node":        q.Node,
		"explanation": g.Explain(q.Node),
		"known":       g.Nodes[q.Node] != nil,
	})
}

// doDiagnose returns the failure signatures the experience holds —
// the governed way an agent asks "what keeps breaking".
func (a *HistoryAdapter) doDiagnose() (json.RawMessage, error) {
	g, err := experience.Reconstruct(a.store, "")
	if err != nil {
		return nil, err
	}
	sigs := research.Diagnose(g)
	return json.Marshal(map[string]any{"signatures": sigs, "count": len(sigs)})
}

// doPropose answers research.propose: interventions for the caller's
// task inside the caller's declared envelope. The envelope is an
// argument — the agent declares its explorable space, the adapter
// does not invent one.
func (a *HistoryAdapter) doPropose(args json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Envelope  *dream.Envelope `json:"envelope"`
		Task      dream.Task      `json:"task"`
		TriedArms []int           `json:"tried_arms"`
	}
	if err := json.Unmarshal(args, &q); err != nil {
		return nil, fmt.Errorf("research.propose arguments: %w", err)
	}
	if q.Envelope == nil {
		return nil, fmt.Errorf("research.propose requires an envelope — the agent declares its exploration space")
	}
	if err := q.Envelope.Validate(); err != nil {
		return nil, fmt.Errorf("envelope invalid: %w", err)
	}
	g, err := experience.Reconstruct(a.store, "")
	if err != nil {
		return nil, err
	}
	events, err := a.store.Query(history.QueryOpts{})
	if err != nil {
		return nil, err
	}
	records, _ := dream.RecordsFromEvents(q.Envelope, events)
	fit, err := dream.Fit(q.Envelope, records)
	if err != nil {
		return nil, err
	}
	tried := map[int]bool{}
	for _, a := range q.TriedArms {
		tried[a] = true
	}
	proposals := research.Plan(g, q.Envelope, fit, q.Task, tried)
	return json.Marshal(map[string]any{
		"proposals":    proposals,
		"model_digest": fit.Digest(),
		"trained_on":   len(records),
	})
}

// doAppend answers history.append: one ad-hoc record, deduped on the
// caller-supplied or content-derived key. The mutation ledger's
// idempotency makes the retry land once; the event dedupe makes the
// record itself idempotent.
func (a *HistoryAdapter) doAppend(args json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Kind        string          `json:"kind"`
		Subject     string          `json:"subject"`
		Correlation string          `json:"correlation"`
		Source      string          `json:"source"`
		DedupeKey   string          `json:"dedupe_key"`
		Payload     json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(args, &q); err != nil {
		return nil, fmt.Errorf("history.append arguments: %w", err)
	}
	if q.Subject == "" || len(q.Payload) == 0 {
		return nil, fmt.Errorf("history.append requires subject and payload")
	}
	kind := q.Kind
	if kind == "" {
		kind = history.KindExperiment
	}
	source := q.Source
	if source == "" {
		source = "governed"
	}
	dedupe := q.DedupeKey
	if dedupe == "" {
		sum := sha256.Sum256(append([]byte(kind+"\x00"+q.Subject+"\x00"+q.Correlation+"\x00"), q.Payload...))
		dedupe = fmt.Sprintf("governed:%x", sum)
	}
	appended, err := a.store.Append(&history.Event{
		DedupeKey: dedupe, Kind: kind, Subject: q.Subject,
		Correlation: q.Correlation, Source: source,
		OccurredAt: time.Now().UnixMilli(), Payload: q.Payload,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"appended": len(appended), "dedupe_key": dedupe})
}

// doRecordDecision answers research.record_decision: an explorer
// decision, refused when its params leave the declared envelope —
// the same guard the CLI enforces, now at the governed boundary.
func (a *HistoryAdapter) doRecordDecision(args json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Envelope *dream.Envelope `json:"envelope"`
		Decision *dream.Decision `json:"decision"`
	}
	if err := json.Unmarshal(args, &q); err != nil {
		return nil, fmt.Errorf("research.record_decision arguments: %w", err)
	}
	if q.Envelope == nil || q.Decision == nil {
		return nil, fmt.Errorf("research.record_decision requires envelope and decision")
	}
	if err := q.Envelope.Validate(); err != nil {
		return nil, err
	}
	if err := dream.RecordDecision(a.store, q.Envelope, q.Decision); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"recorded": true})
}

// doCheckpoint answers history.checkpoint: a witness-signed
// checkpoint into the caller-named dir. The witness key comes from
// deployment configuration, never the request — an agent cannot name
// its own witness.
func (a *HistoryAdapter) doCheckpoint(args json.RawMessage) (json.RawMessage, error) {
	var q struct {
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(args, &q); err != nil || q.Dir == "" {
		return nil, fmt.Errorf("history.checkpoint requires dir")
	}
	if a.witnessKey == "" {
		return nil, fmt.Errorf("no witness configured — CRABEDENCE_HISTORY_WITNESS_KEY is required for checkpoints; witnessed state is not minted under an unnamed identity")
	}
	witness, err := evidence.LoadOrCreateSigner(a.witnessKey)
	if err != nil {
		return nil, fmt.Errorf("witness key: %w", err)
	}
	cp, err := a.store.WriteCheckpoint(q.Dir, witness)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"sequence":   cp.Sequence,
		"chain_head": cp.ChainHead,
		"store_id":   cp.StoreID,
		"witness":    cp.Signer,
	})
}

// RegisterHistoryCapabilities registers the governed memory reads
// and mutations. Registration is unconditional — the release's policy
// surface — while adapter availability is deployment wiring.
func RegisterHistoryCapabilities(reg *capability.Registry) error {
	reads := []capability.CapabilityDescriptor{
		{
			ID:             "history.query",
			ExecutionClass: capability.ClassRead,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "history.query",
				GrantRequired: false,
			},
			Schema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"kinds": {"type": "array", "items": {"type": "string"}},
					"subject": {"type": "string"},
					"correlation": {"type": "string"},
					"since": {"type": "integer", "minimum": 0},
					"until": {"type": "integer", "minimum": 0},
					"limit": {"type": "integer", "minimum": 1, "maximum": 500}
				},
				"additionalProperties": false
			}`),
		},
		{
			ID:             "history.verify",
			ExecutionClass: capability.ClassRead,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "history.verify",
				GrantRequired: false,
			},
			Schema: json.RawMessage(`{"type": "object", "properties": {}, "additionalProperties": false}`),
		},
		{
			ID:             "history.explain",
			ExecutionClass: capability.ClassRead,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "history.explain",
				GrantRequired: false,
			},
			Schema: json.RawMessage(`{
				"type": "object",
				"properties": {"node": {"type": "string", "minLength": 1}},
				"required": ["node"],
				"additionalProperties": false
			}`),
		},
		{
			ID:             "research.diagnose",
			ExecutionClass: capability.ClassRead,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "research.diagnose",
				GrantRequired: false,
			},
			Schema: json.RawMessage(`{"type": "object", "properties": {}, "additionalProperties": false}`),
		},
		{
			ID:             "research.propose",
			ExecutionClass: capability.ClassRead,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "research.propose",
				GrantRequired: false,
			},
			Schema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"envelope": {"type": "object"},
					"task": {"type": "object"},
					"tried_arms": {"type": "array", "items": {"type": "integer"}}
				},
				"required": ["envelope", "task"],
				"additionalProperties": false
			}`),
		},
	}
	mutations := []capability.CapabilityDescriptor{
		{
			ID:             "history.append",
			ExecutionClass: capability.ClassMutation,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "history.append",
				GrantRequired: true,
			},
			Schema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"kind": {"type": "string"},
					"subject": {"type": "string", "minLength": 1},
					"correlation": {"type": "string"},
					"source": {"type": "string"},
					"dedupe_key": {"type": "string"},
					"payload": {}
				},
				"required": ["subject", "payload"],
				"additionalProperties": false
			}`),
		},
		{
			ID:             "research.record_decision",
			ExecutionClass: capability.ClassMutation,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "research.record_decision",
				GrantRequired: true,
			},
			Schema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"envelope": {"type": "object"},
					"decision": {"type": "object"}
				},
				"required": ["envelope", "decision"],
				"additionalProperties": false
			}`),
		},
		{
			ID:             "history.checkpoint",
			ExecutionClass: capability.ClassMutation,
			AdapterID:      historyAdapterID,
			AuthorityPolicy: capability.AuthorityPolicy{
				ID:            "history.checkpoint",
				GrantRequired: true,
			},
			Schema: json.RawMessage(`{
				"type": "object",
				"properties": {"dir": {"type": "string", "minLength": 1}},
				"required": ["dir"],
				"additionalProperties": false
			}`),
		},
	}
	for _, d := range append(reads, mutations...) {
		if err := reg.Register(d); err != nil {
			return fmt.Errorf("register %s: %w", d.ID, err)
		}
	}
	return nil
}

// RegisterHistoryReads binds the READ capabilities to the DIRECT
// read registry, projecting through the adapter — exactly one
// implementation serves both routes.
func RegisterHistoryReads(reg *DirectReadRegistry, adapter *HistoryAdapter) error {
	for _, id := range []string{"history.query", "history.verify", "history.explain", "research.diagnose", "research.propose"} {
		capID := id
		if err := reg.Register(capID, func(ctx context.Context, call CallContext) (json.RawMessage, error) {
			resp := adapter.Execute(ctx, Request{
				Capability: capID,
				Arguments:  call.Arguments,
				Authority:  RequestAuthority{Principal: call.Principal},
			}, capability.ResolvedDescriptor{
				ID:             capID,
				ExecutionClass: capability.ClassRead,
				ExecutionRoute: capability.RouteDirect,
				AdapterID:      historyAdapterID,
			})
			if resp.Status != StatusSucceeded {
				return nil, fmt.Errorf("%s failed: %s", capID, resp.Error)
			}
			return resp.Result, nil
		}); err != nil {
			return err
		}
	}
	return nil
}
