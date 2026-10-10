package execution

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// ProviderGate bounds and observes provider dispatch per adapter.
//
// The executor's provider ceiling already bounds how long one call may
// hold a lease, but Go cannot kill a goroutine whose adapter never
// returns: without a bound, a wedged provider accumulates goroutines —
// and leases — without limit. The gate adds three properties per
// provider:
//
//   - a bounded number of simultaneously executing provider calls;
//   - an explicit count of calls that outlived the ceiling and are
//     still running (wedged), so a leaked goroutine is visible rather
//     than implied;
//   - a health state (healthy, degraded, open) derived from consecutive
//     ambiguous dispatch outcomes. Provider health is deliberately
//     separate from individual effect state: an effect can be UNKNOWN
//     while its provider is merely degraded.
//
// Reconciliation never acquires the gate. The exact provider failure
// that strands a record in UNKNOWN must not also prevent the lookup
// that resolves it, so only the dispatch path consumes capacity;
// reconciliation outcomes are counted (see RecordReconciliationFailure)
// without gating anything.
type ProviderGate struct {
	cfg ProviderGateConfig
	// now is a test seam for the open-circuit cooldown.
	now func() time.Time

	mu        sync.Mutex
	providers map[string]*providerState
}

var (
	// ErrProviderSaturated means every dispatch slot for the provider
	// is in use. The call was refused before the provider was invoked.
	ErrProviderSaturated = errors.New("provider dispatch capacity exhausted")
	// ErrProviderCircuitOpen means the provider's consecutive-failure
	// budget is exhausted. Dispatch is refused until the cooldown
	// elapses and a probe succeeds.
	ErrProviderCircuitOpen = errors.New("provider circuit is open")
)

// ProviderHealth is the coarse health of one provider's dispatch path.
type ProviderHealth string

const (
	ProviderHealthy  ProviderHealth = "healthy"
	ProviderDegraded ProviderHealth = "degraded"
	ProviderOpen     ProviderHealth = "open"
)

// ProviderLane identifies which capacity budget a provider call draws
// from. Read and mutation dispatches share the bounded dispatch pool —
// the bound protects process resources against a wedged provider, and
// both classes equally consume it. Reconciliation draws from a small
// reserved budget so recovery lookups keep running while the dispatch
// pool is saturated or the circuit is open: the exact provider failure
// that strands records in UNKNOWN must not also prevent the lookup
// that resolves them.
type ProviderLane string

const (
	// LaneRead is a direct-read provider dispatch (READ class).
	LaneRead ProviderLane = "read"
	// LaneMutation is an effect dispatch (MUTATION/CRITICAL class).
	LaneMutation ProviderLane = "mutation"
	// LaneReconciliation is a recovery resolver's provider lookup.
	// It draws from the reserved reconciliation budget and is never
	// refused by an open circuit — the circuit guards dispatch, not
	// resolution of the records dispatch stranded.
	LaneReconciliation ProviderLane = "reconciliation"
)

// ProviderGateConfig tunes one gate.
type ProviderGateConfig struct {
	// MaxConcurrent bounds simultaneously executing provider calls.
	MaxConcurrent int
	// DegradedAfter is the number of consecutive ambiguous dispatch
	// outcomes after which the provider reports degraded.
	DegradedAfter int
	// OpenAfter is the number of consecutive ambiguous dispatch
	// outcomes after which dispatch is refused entirely.
	OpenAfter int
	// OpenCooldown is how long an open circuit refuses new dispatch
	// before admitting a single probe.
	OpenCooldown time.Duration
	// ReconMaxConcurrent is the reserved reconciliation-lane budget:
	// provider lookups that may proceed regardless of dispatch
	// saturation or circuit state.
	ReconMaxConcurrent int
}

// DefaultProviderGateConfig returns the production policy. The
// concurrency bound is deliberately generous: it exists to bound
// runaway goroutines, not to throttle ordinary load.
func DefaultProviderGateConfig() ProviderGateConfig {
	return ProviderGateConfig{
		MaxConcurrent:      64,
		DegradedAfter:      5,
		OpenAfter:          10,
		OpenCooldown:       30 * time.Second,
		ReconMaxConcurrent: 4,
	}
}

func (c ProviderGateConfig) withDefaults() ProviderGateConfig {
	d := DefaultProviderGateConfig()
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = d.MaxConcurrent
	}
	if c.DegradedAfter <= 0 {
		c.DegradedAfter = d.DegradedAfter
	}
	if c.OpenAfter <= 0 {
		c.OpenAfter = d.OpenAfter
	}
	if c.OpenCooldown <= 0 {
		c.OpenCooldown = d.OpenCooldown
	}
	if c.ReconMaxConcurrent <= 0 {
		c.ReconMaxConcurrent = d.ReconMaxConcurrent
	}
	return c
}

// ProviderHealthSnapshot is the observable state of one provider.
type ProviderHealthSnapshot struct {
	ProviderID             string         `json:"provider_id"`
	Health                 ProviderHealth `json:"health"`
	InFlight               int            `json:"in_flight"`
	ReadInFlight           int            `json:"read_in_flight"`
	MutationInFlight       int            `json:"mutation_in_flight"`
	ReconInFlight          int            `json:"recon_in_flight"`
	Wedged                 int            `json:"wedged"`
	ConsecutiveFailures    int            `json:"consecutive_failures"`
	Timeouts               int64          `json:"timeouts"`
	TransportFailures      int64          `json:"transport_failures"`
	LocalAmbiguities       int64          `json:"local_ambiguities"`
	ReconciliationFailures int64          `json:"reconciliation_failures"`
	LastFailure            string         `json:"last_failure,omitempty"`
}

type providerState struct {
	inFlight               int // dispatch-pool slots in use (read + mutation)
	inFlightRead           int
	inFlightMutation       int
	inFlightRecon          int
	wedged                 int
	consecutiveFailures    int
	openedAt               time.Time
	probeInFlight          bool
	lastFailure            string
	timeouts               int64
	transportFailures      int64
	localAmbiguities       int64
	reconciliationFailures int64
}

// NewProviderGate creates a gate. Zero config fields take the
// production defaults.
func NewProviderGate(cfg ProviderGateConfig) *ProviderGate {
	return &ProviderGate{
		cfg:       cfg.withDefaults(),
		now:       time.Now,
		providers: make(map[string]*providerState),
	}
}

// Config returns the effective configuration.
func (g *ProviderGate) Config() ProviderGateConfig { return g.cfg }

// setClock installs a test clock.
func (g *ProviderGate) setClock(now func() time.Time) { g.now = now }

func (g *ProviderGate) state(providerID string) *providerState {
	st, ok := g.providers[providerID]
	if !ok {
		st = &providerState{}
		g.providers[providerID] = st
	}
	return st
}

// Acquire reserves one provider slot on the given lane. It never
// blocks: a saturated or open provider is refused immediately, so a
// caller converges without spawning another goroutine. The
// reconciliation lane draws from its own reserved budget and bypasses
// the circuit — a refused recon call means every reserved slot is in
// use, nothing more. The returned lease must be released exactly once
// when the provider call finishes.
func (g *ProviderGate) Acquire(providerID string, lane ProviderLane) (*ProviderLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(providerID)
	if lane == LaneReconciliation {
		if st.inFlightRecon >= g.cfg.ReconMaxConcurrent {
			return nil, fmt.Errorf("%w: %s reconciliation lane (%d in flight)", ErrProviderSaturated, providerID, st.inFlightRecon)
		}
		st.inFlightRecon++
		return &ProviderLease{gate: g, providerID: providerID, lane: lane}, nil
	}
	probe, err := g.admitLocked(providerID, st)
	if err != nil {
		return nil, err
	}
	st.inFlight++
	switch lane {
	case LaneRead:
		st.inFlightRead++
	default:
		st.inFlightMutation++
	}
	return &ProviderLease{gate: g, providerID: providerID, probe: probe, lane: lane}, nil
}

// admitLocked decides whether one call may start, implementing the
// circuit: an open provider refuses until the cooldown elapses, then
// admits exactly one probe.
func (g *ProviderGate) admitLocked(providerID string, st *providerState) (probe bool, err error) {
	if st.consecutiveFailures < g.cfg.OpenAfter {
		if st.inFlight >= g.cfg.MaxConcurrent {
			return false, fmt.Errorf("%w: %s (%d in flight)", ErrProviderSaturated, providerID, st.inFlight)
		}
		return false, nil
	}
	if st.probeInFlight {
		return false, fmt.Errorf("%w: %s (probe in flight)", ErrProviderCircuitOpen, providerID)
	}
	if !st.openedAt.IsZero() && g.now().Sub(st.openedAt) >= g.cfg.OpenCooldown {
		if st.inFlight >= g.cfg.MaxConcurrent {
			return false, fmt.Errorf("%w: %s (%d in flight)", ErrProviderSaturated, providerID, st.inFlight)
		}
		st.probeInFlight = true
		return true, nil
	}
	return false, fmt.Errorf("%w: %s (%s)", ErrProviderCircuitOpen, providerID, st.lastFailure)
}

// RecordSuccess records a definitive provider answer: the provider is
// answering, so the failure streak resets and a probe is considered
// successful.
func (g *ProviderGate) RecordSuccess(providerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(providerID)
	st.consecutiveFailures = 0
	st.openedAt = time.Time{}
	st.probeInFlight = false
}

// RecordAmbiguous records a post-dispatch ambiguous outcome (UNKNOWN):
// the provider did not give a usable answer. Consecutive ambiguous
// outcomes degrade the provider and eventually open the circuit.
func (g *ProviderGate) RecordAmbiguous(providerID string, reason string) {
	g.RecordAmbiguousOutcome(providerID, true, reason)
}

// RecordAmbiguousOutcome records an ambiguous outcome attributed to a
// causality class. Only provider-side ambiguity degrades health —
// timeouts, transport failures, protocol ambiguity, and provider-side
// unavailability are evidence the provider cannot answer. A local
// cause (executor cancellation, a deadline that fired before dispatch,
// a policy refusal) says nothing about provider health: it is counted
// for visibility but never advances the failure streak or opens the
// circuit.
func (g *ProviderGate) RecordAmbiguousOutcome(providerID string, providerSide bool, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(providerID)
	if !providerSide {
		st.localAmbiguities++
		st.probeInFlight = false
		return
	}
	st.consecutiveFailures++
	st.transportFailures++
	st.lastFailure = reason
	st.probeInFlight = false
	if st.consecutiveFailures >= g.cfg.OpenAfter {
		st.openedAt = g.now()
	}
}

// RecordReconciliationFailure counts a failed or inconclusive recovery
// lookup. Reconciliation failures are observed, never dispatch-gating:
// they do not open the circuit, because refusing dispatch would not
// help resolve records that are already ambiguous.
func (g *ProviderGate) RecordReconciliationFailure(providerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state(providerID).reconciliationFailures++
}

// Snapshot returns the health view for every observed provider,
// ordered by provider ID.
func (g *ProviderGate) Snapshot() []ProviderHealthSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	ids := make([]string, 0, len(g.providers))
	for id := range g.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ProviderHealthSnapshot, 0, len(ids))
	for _, id := range ids {
		st := g.providers[id]
		out = append(out, ProviderHealthSnapshot{
			ProviderID:             id,
			Health:                 g.healthLocked(st),
			InFlight:               st.inFlight,
			ReadInFlight:           st.inFlightRead,
			MutationInFlight:       st.inFlightMutation,
			ReconInFlight:          st.inFlightRecon,
			Wedged:                 st.wedged,
			ConsecutiveFailures:    st.consecutiveFailures,
			Timeouts:               st.timeouts,
			TransportFailures:      st.transportFailures,
			LocalAmbiguities:       st.localAmbiguities,
			ReconciliationFailures: st.reconciliationFailures,
			LastFailure:            st.lastFailure,
		})
	}
	return out
}

// Health reports the current health of one provider.
func (g *ProviderGate) Health(providerID string) ProviderHealth {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.healthLocked(g.state(providerID))
}

func (g *ProviderGate) healthLocked(st *providerState) ProviderHealth {
	switch {
	case st.consecutiveFailures >= g.cfg.OpenAfter:
		return ProviderOpen
	case st.consecutiveFailures >= g.cfg.DegradedAfter:
		return ProviderDegraded
	default:
		return ProviderHealthy
	}
}

// ProviderLease is one dispatch-capacity reservation. It is released
// when the provider call finishes — for a wedged call, only when the
// goroutine actually returns, so a leaked goroutine keeps its slot
// reserved and stays visible in the snapshot.
type ProviderLease struct {
	gate       *ProviderGate
	providerID string
	probe      bool
	lane       ProviderLane
	once       sync.Once
	wedged     atomic.Bool
}

// Release returns the lane's slot.
func (l *ProviderLease) Release() {
	l.once.Do(func() {
		l.gate.mu.Lock()
		defer l.gate.mu.Unlock()
		st := l.gate.state(l.providerID)
		if l.lane == LaneReconciliation {
			if st.inFlightRecon > 0 {
				st.inFlightRecon--
			}
			return
		}
		if st.inFlight > 0 {
			st.inFlight--
		}
		switch l.lane {
		case LaneRead:
			if st.inFlightRead > 0 {
				st.inFlightRead--
			}
		default:
			if st.inFlightMutation > 0 {
				st.inFlightMutation--
			}
		}
		if l.wedged.Load() && st.wedged > 0 {
			st.wedged--
		}
		if l.probe {
			st.probeInFlight = false
		}
	})
}

// MarkWedged records that the call outlived the executor ceiling and
// its goroutine is still running.
func (l *ProviderLease) MarkWedged() {
	if l.wedged.CompareAndSwap(false, true) {
		l.gate.mu.Lock()
		l.gate.state(l.providerID).wedged++
		l.gate.mu.Unlock()
	}
}

// MarkTimeout records that the executor ceiling (or the caller's
// deadline) fired for this call.
func (l *ProviderLease) MarkTimeout() {
	l.gate.mu.Lock()
	l.gate.state(l.providerID).timeouts++
	l.gate.mu.Unlock()
}

// ObserveResolver wraps a recovery resolver so reconciliation
// outcomes are counted on the gate. The wrapper never acquires
// dispatch capacity: reconciliation must proceed while the dispatch
// path is saturated or open.
func (g *ProviderGate) ObserveResolver(providerID string, inner idempotency.RecoveryResolver) idempotency.RecoveryResolver {
	return &observedResolver{gate: g, providerID: providerID, inner: inner}
}

type observedResolver struct {
	gate       *ProviderGate
	providerID string
	inner      idempotency.RecoveryResolver
}

func (r *observedResolver) Resolve(ctx context.Context, record *idempotency.Record) (idempotency.RecoveryResult, error) {
	// Reconciliation draws from the reserved lane — bounded, but never
	// circuit-gated: the exact provider failure that stranded records
	// must not prevent the lookup resolving them. A saturated lane
	// defers the attempt; the record stays UNKNOWN for the next cycle.
	lease, err := r.gate.Acquire(r.providerID, LaneReconciliation)
	if err != nil {
		r.gate.RecordReconciliationFailure(r.providerID)
		return idempotency.RecoveryResult{}, err
	}
	defer lease.Release()
	result, err := r.inner.Resolve(ctx, record)
	if err != nil || result.Decision == idempotency.RecoveryUnknown {
		r.gate.RecordReconciliationFailure(r.providerID)
	}
	return result, err
}
