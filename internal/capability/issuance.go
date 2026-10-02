package capability

import (
	"fmt"
	"sort"
)

// Issuance-scope policy.
//
// Grant.AllowsResource treats an absent resource dimension as intentionally
// unconstrained. That semantics is load-bearing: grants issued before resource
// constraints existed must still verify, and the evaluator is part of the
// signed-grant surface. It cannot change without invalidating historical
// signatures, so it does not change here.
//
// What must not be load-bearing is *omission* at issuance: a grant minted with
// no constraint on a dimension a descriptor declares is silently broader than
// the issuer may have meant — capability github.issue.create with no
// repo constraint authorizes every repository the service credential can
// reach. The issuance boundary therefore validates scope declarations against
// the registry's resolved descriptors before a grant is created: every
// descriptor-declared dimension must be addressed exactly once, by a concrete
// constraint or by an explicit unconstrained acknowledgement. A dimension the
// issuer never named is a rejection, not a wildcard.
//
// The explicit acknowledgement still materializes as grant material: an
// unconstrained dimension is stored as the single value "*", so the issued
// grant records that its breadth was deliberate rather than inherited from an
// unset field. Verifying or evaluating such a grant uses the same
// AllowsResource semantics as any other grant — the policy lives at issuance,
// not in the evaluator.

// IssuanceWildcardCapability is the capability-list entry that requests a
// grant over every capability in the issuance catalog.
const IssuanceWildcardCapability = "*"

// issuanceRejection prefixes every scope error so an operator — and a test —
// can tell a policy refusal from a malformed flag.
const issuanceRejection = "grant issuance rejected: "

// RequiredResourceDimensions returns the sorted set of resource dimensions the
// requested capabilities declare through AuthorityPolicy.ResourceArguments.
// A selection of ["*"] covers every capability in the registry; named
// capabilities must resolve, because a capability the catalog cannot show is a
// capability whose declared dimensions the issuer never saw.
func (r *Registry) RequiredResourceDimensions(capabilities []string) ([]string, error) {
	descriptors, err := r.issuanceDescriptors(capabilities)
	if err != nil {
		return nil, err
	}
	required := map[string]struct{}{}
	for _, descriptor := range descriptors {
		for dimension := range descriptor.AuthorityPolicy.ResourceArguments {
			required[dimension] = struct{}{}
		}
	}
	dimensions := make([]string, 0, len(required))
	for dimension := range required {
		dimensions = append(dimensions, dimension)
	}
	sort.Strings(dimensions)
	return dimensions, nil
}

// issuanceDescriptors resolves the capability selection to descriptors.
func (r *Registry) issuanceDescriptors(capabilities []string) ([]ResolvedDescriptor, error) {
	if len(capabilities) == 0 {
		return nil, fmt.Errorf(issuanceRejection+"capability list is empty; name at least one capability or pass %q for all", IssuanceWildcardCapability)
	}
	if len(capabilities) == 1 && capabilities[0] == IssuanceWildcardCapability {
		ids := r.List()
		descriptors := make([]ResolvedDescriptor, 0, len(ids))
		for _, id := range ids {
			descriptor, ok := r.Lookup(id)
			if !ok {
				return nil, fmt.Errorf(issuanceRejection+"registry listed %q but cannot resolve its descriptor", id)
			}
			descriptors = append(descriptors, descriptor)
		}
		return descriptors, nil
	}
	descriptors := make([]ResolvedDescriptor, 0, len(capabilities))
	seen := map[string]struct{}{}
	for _, id := range capabilities {
		if id == IssuanceWildcardCapability {
			return nil, fmt.Errorf(issuanceRejection+"wildcard capability %q cannot be combined with named capabilities", IssuanceWildcardCapability)
		}
		if id == "" {
			return nil, fmt.Errorf(issuanceRejection + "capability id must not be empty")
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		descriptor, ok := r.Lookup(id)
		if !ok {
			return nil, fmt.Errorf(issuanceRejection+"capability %q is not in the issuance catalog; its declared resource dimensions cannot be verified", id)
		}
		descriptors = append(descriptors, descriptor)
	}
	return descriptors, nil
}

// ValidateIssuanceScope checks the issuer's scope declarations against the
// dimensions the requested capabilities declare, and returns the constraint
// material the grant should carry.
//
// Rules, all fail-closed:
//   - every descriptor-declared dimension is addressed exactly once: either by
//     a non-empty constraint value list or by an explicit unconstrained
//     acknowledgement;
//   - a dimension no requested capability declares is rejected, whether it is
//     constrained or acknowledged;
//   - a dimension declared both ways is rejected;
//   - "*" is not a legal constraint value: it would smuggle a wildcard back
//     through the concrete path — deliberate breadth must use the explicit
//     acknowledgement;
//   - duplicate acknowledgements, and duplicate constraint values within one
//     dimension, are rejected: repeated declarations hide typos.
//
// Dimensions acknowledged unconstrained are materialized as the single value
// "*" in the returned constraints, so the issued grant records its breadth as
// a deliberate choice. The returned map is a copy; inputs are not mutated.
func (r *Registry) ValidateIssuanceScope(
	capabilities []string,
	constraints map[string][]string,
	unconstrained []string,
) (map[string][]string, error) {
	required, err := r.RequiredResourceDimensions(capabilities)
	if err != nil {
		return nil, err
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, dimension := range required {
		requiredSet[dimension] = struct{}{}
	}

	effective := make(map[string][]string, len(constraints)+len(unconstrained))
	for dimension, values := range constraints {
		if _, known := requiredSet[dimension]; !known {
			return nil, fmt.Errorf(issuanceRejection+"unknown resource dimension %q — no requested capability declares it", dimension)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf(issuanceRejection+"resource dimension %q has an empty constraint list; pass %q to declare deliberate wildcard scope", dimension, "--unconstrained "+dimension)
		}
		seenValues := map[string]struct{}{}
		cleaned := make([]string, 0, len(values))
		for _, value := range values {
			if value == "" {
				return nil, fmt.Errorf(issuanceRejection+"resource dimension %q has an empty constraint value", dimension)
			}
			if value == IssuanceWildcardCapability {
				return nil, fmt.Errorf(issuanceRejection+"constraint value %q for dimension %q is wildcard shorthand; use %q to declare deliberate wildcard scope", value, dimension, "--unconstrained "+dimension)
			}
			if _, duplicate := seenValues[value]; duplicate {
				return nil, fmt.Errorf(issuanceRejection+"constraint %s=%s declared twice", dimension, value)
			}
			seenValues[value] = struct{}{}
			cleaned = append(cleaned, value)
		}
		effective[dimension] = cleaned
	}

	acknowledged := map[string]struct{}{}
	for _, dimension := range unconstrained {
		if dimension == "" {
			return nil, fmt.Errorf(issuanceRejection + "unconstrained dimension name must not be empty")
		}
		if _, known := requiredSet[dimension]; !known {
			return nil, fmt.Errorf(issuanceRejection+"unknown resource dimension %q — no requested capability declares it", dimension)
		}
		if _, conflict := constraints[dimension]; conflict {
			return nil, fmt.Errorf(issuanceRejection+"resource dimension %q declared both constrained and unconstrained", dimension)
		}
		if _, duplicate := acknowledged[dimension]; duplicate {
			return nil, fmt.Errorf(issuanceRejection+"resource dimension %q acknowledged unconstrained twice", dimension)
		}
		acknowledged[dimension] = struct{}{}
		effective[dimension] = []string{IssuanceWildcardCapability}
	}

	missing := make([]string, 0, len(required))
	for _, dimension := range required {
		if _, addressed := effective[dimension]; !addressed {
			missing = append(missing, dimension)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(issuanceRejection+"resource dimension %q requires either a constraint or an explicit unconstrained acknowledgement", missing[0])
	}
	if len(effective) == 0 {
		return nil, nil
	}
	return effective, nil
}
