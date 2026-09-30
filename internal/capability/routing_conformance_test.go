package capability

import (
	"strings"
	"testing"
)

// TestRoutingConformance proves that the three-dimensional routing model
// is enforced at registration and produces correct routing decisions.
//
// These tests verify the security property: invalid combinations cannot
// enter the active registry, and valid combinations route correctly.
func TestRoutingConformance(t *testing.T) {
	t.Run("PURE/NONE/LOCAL never reaches Crabedence", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(CapabilityDescriptor{
			ID:             "math.calculate",
			ExecutionClass: ClassPure,
			AdapterID:      "local-math",
		})
		if err != nil {
			t.Fatal(err)
		}
		desc, ok := r.Lookup("math.calculate")
		if !ok {
			t.Fatal("expected capability in registry")
		}
		if desc.ExecutionRoute != RouteLocal {
			t.Errorf("expected LOCAL, got %s", desc.ExecutionRoute)
		}
		if desc.AssuranceProfile != AssuranceNone {
			t.Errorf("expected NONE, got %s", desc.AssuranceProfile)
		}
	})

	t.Run("READ/STANDARD/DIRECT executes through direct adapter", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(CapabilityDescriptor{
			ID:             "weather.current",
			ExecutionClass: ClassRead,
			AdapterID:      "weather-adapter",
		})
		if err != nil {
			t.Fatal(err)
		}
		desc, ok := r.Lookup("weather.current")
		if !ok {
			t.Fatal("expected capability in registry")
		}
		if desc.ExecutionRoute != RouteDirect {
			t.Errorf("expected DIRECT, got %s", desc.ExecutionRoute)
		}
		if desc.AssuranceProfile != AssuranceStandard {
			t.Errorf("expected STANDARD, got %s", desc.AssuranceProfile)
		}
	})

	t.Run("READ/HIGH_ASSURANCE/CRABEDENCE cannot be downgraded to DIRECT", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(CapabilityDescriptor{
			ID:               "medical.record.read",
			ExecutionClass:   ClassRead,
			AssuranceProfile: AssuranceHighAssurance,
			AdapterID:        "medical-adapter",
		})
		if err != nil {
			t.Fatal(err)
		}
		desc, ok := r.Lookup("medical.record.read")
		if !ok {
			t.Fatal("expected capability in registry")
		}
		if desc.ExecutionRoute != RouteCrabedence {
			t.Errorf("expected CRABEDENCE, got %s", desc.ExecutionRoute)
		}
		if desc.AssuranceProfile != AssuranceHighAssurance {
			t.Errorf("expected HIGH_ASSURANCE, got %s", desc.AssuranceProfile)
		}

		// Explicitly trying to force DIRECT must fail at registration
		err = r.Register(CapabilityDescriptor{
			ID:               "medical.record.read.bypass",
			ExecutionClass:   ClassRead,
			AssuranceProfile: AssuranceHighAssurance,
			ExecutionRoute:   RouteDirect, // attempt bypass
			AdapterID:        "medical-adapter",
		})
		if err == nil {
			t.Fatal("expected registration to fail for READ/HIGH_ASSURANCE/DIRECT")
		}
	})

	t.Run("MUTATION/DURABLE/CRABEDENCE routes to durable execution", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(CapabilityDescriptor{
			ID:             "home.light.set",
			ExecutionClass: ClassMutation,
			AdapterID:      "home-adapter",
		})
		if err != nil {
			t.Fatal(err)
		}
		desc, ok := r.Lookup("home.light.set")
		if !ok {
			t.Fatal("expected capability in registry")
		}
		if desc.ExecutionRoute != RouteCrabedence {
			t.Errorf("expected CRABEDENCE, got %s", desc.ExecutionRoute)
		}
		if desc.AssuranceProfile != AssuranceDurable {
			t.Errorf("expected DURABLE, got %s", desc.AssuranceProfile)
		}
	})

	t.Run("CRITICAL/HIGH_ASSURANCE/CRABEDENCE requires authority+evidence", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(CapabilityDescriptor{
			ID:             "email.send",
			ExecutionClass: ClassCritical,
			AdapterID:      "gmail-adapter",
			AuthorityPolicy: AuthorityPolicy{
				ID:            "email.send",
				GrantRequired: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		desc, ok := r.Lookup("email.send")
		if !ok {
			t.Fatal("expected capability in registry")
		}
		if desc.ExecutionRoute != RouteCrabedence {
			t.Errorf("expected CRABEDENCE, got %s", desc.ExecutionRoute)
		}
		if desc.AssuranceProfile != AssuranceHighAssurance {
			t.Errorf("expected HIGH_ASSURANCE, got %s", desc.AssuranceProfile)
		}
		if !desc.AssuranceProfile.RequiresEvidence() {
			t.Error("expected evidence requirement")
		}
		if !desc.AuthorityPolicy.GrantRequired {
			t.Error("expected grant required")
		}
	})

	t.Run("invalid descriptor combinations cannot enter active registry", func(t *testing.T) {
		invalid := []struct {
			name     string
			desc     CapabilityDescriptor
			errorMsg string
		}{
			{
				name: "CRITICAL/HIGH_ASSURANCE/LOCAL",
				desc: CapabilityDescriptor{
					ID:               "bad.critical.local",
					ExecutionClass:   ClassCritical,
					AssuranceProfile: AssuranceHighAssurance,
					ExecutionRoute:   RouteLocal,
					AdapterID:        "test",
				},
				errorMsg: "route LOCAL requires effect PURE",
			},
			{
				name: "MUTATION/DURABLE/DIRECT",
				desc: CapabilityDescriptor{
					ID:               "bad.mutation.direct",
					ExecutionClass:   ClassMutation,
					AssuranceProfile: AssuranceDurable,
					ExecutionRoute:   RouteDirect,
					AdapterID:        "test",
				},
				errorMsg: "route DIRECT cannot handle effect MUTATION",
			},
			{
				name: "READ/HIGH_ASSURANCE/DIRECT",
				desc: CapabilityDescriptor{
					ID:               "bad.read.high.direct",
					ExecutionClass:   ClassRead,
					AssuranceProfile: AssuranceHighAssurance,
					ExecutionRoute:   RouteDirect,
					AdapterID:        "test",
				},
				errorMsg: "route DIRECT cannot satisfy assurance HIGH_ASSURANCE",
			},
			{
				name: "PURE/HIGH_ASSURANCE/LOCAL",
				desc: CapabilityDescriptor{
					ID:               "bad.pure.high.local",
					ExecutionClass:   ClassPure,
					AssuranceProfile: AssuranceHighAssurance,
					ExecutionRoute:   RouteLocal,
					AdapterID:        "test",
				},
				errorMsg: "route LOCAL cannot satisfy assurance HIGH_ASSURANCE",
			},
			{
				name: "PURE/STANDARD/LOCAL",
				desc: CapabilityDescriptor{
					ID:               "bad.pure.std.local",
					ExecutionClass:   ClassPure,
					AssuranceProfile: AssuranceStandard,
					ExecutionRoute:   RouteLocal,
					AdapterID:        "test",
				},
				errorMsg: "route LOCAL cannot satisfy assurance STANDARD",
			},
			{
				name: "MUTATION/HIGH_ASSURANCE/DIRECT",
				desc: CapabilityDescriptor{
					ID:               "bad.mutation.high.direct",
					ExecutionClass:   ClassMutation,
					AssuranceProfile: AssuranceHighAssurance,
					ExecutionRoute:   RouteDirect,
					AdapterID:        "test",
				},
				errorMsg: "route DIRECT cannot handle effect MUTATION",
			},
		}

		for _, tt := range invalid {
			t.Run(tt.name, func(t *testing.T) {
				r := NewRegistry()
				err := r.Register(tt.desc)
				if err == nil {
					t.Fatal("expected registration to fail")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}

				// Verify it did not enter the registry
				if _, ok := r.Lookup(tt.desc.ID); ok {
					t.Fatal("invalid capability should not be in registry")
				}
			})
		}
	})
}
