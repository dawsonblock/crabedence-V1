package history

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Assessment results are a closed, derived set — a verifier's
// verdict under one specific policy, never a property of the
// observation itself. The observation records what was found; the
// assessment records what a named verifier concluded about it under
// a named trust set at a point in time.
const (
	// AssessmentVerified: the verifier's rules and its trusted-signer
	// set both passed — the record can feed learning that requires
	// provenance-verified history.
	AssessmentVerified = "VERIFIED"
	// AssessmentRejected: the verifier evaluated the record and it
	// failed — forged signature, broken chain, contradictory facts.
	// Rejection is durable knowledge, not absence of verification.
	AssessmentRejected = "REJECTED"
	// AssessmentUnverified: the record exists but no applicable
	// assessment has run — memory reports it, learning must not
	// trust it.
	AssessmentUnverified = "UNVERIFIED"
	// AssessmentConflicted: applicable verifiers disagree — the
	// store keeps both verdicts and reports the conflict rather
	// than silently picking a winner.
	AssessmentConflicted = "CONFLICTED"
	// AssessmentStale: the latest applicable assessment was produced
	// under a different trust set or rules version than the one the
	// caller asks with — stale is a state, not a deletion: the old
	// verdict stays auditable and never silently upgrades.
	AssessmentStale = "STALE"
)

// Assessment is one verification verdict about one stored
// observation. Assessments are append-only: a later verdict under a
// different policy is a new row, so the audit trail shows who
// concluded what, under which rules, against which inputs, and when.
// Identity = (subject, verifier, rules, trust-set, input): the same
// verdict re-derived from the same inputs is idempotent; a different
// verdict under the same inputs is a conflict to record, not to hide.
type Assessment struct {
	Seq          int64
	SubjectKey   string // dedupe key of the observation being assessed
	Verifier     string // verifier identity — who ran the check
	RulesVersion string // the verification rules applied
	TrustSetSHA  string // digest of the trusted-signer set in force
	InputSHA     string // digest of the assessed evidence input
	Result       string
	Detail       string
	AssessedAtMS int64
}

// trustSetDomain separates the trust-set digest so it cannot collide
// with a payload digest or a chain head.
const trustSetDomain = "crabedence.history-trustset.v1\x00"

// TrustSetSHA256 digests a trusted-signer set — sorted, length-safe —
// so an assessment names exactly which trust policy produced it.
func TrustSetSHA256(trusted map[string]bool) string {
	keys := make([]string, 0, len(trusted))
	for k, v := range trusted {
		if v {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(trustSetDomain))
	var l [4]byte
	for _, k := range keys {
		binary.BigEndian.PutUint32(l[:], uint32(len(k)))
		h.Write(l[:])
		h.Write([]byte(k))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RecordAssessment appends assessments. Identical re-assessment —
// same subject, verifier, rules, trust set, input, and result — is
// skipped; every distinct verdict is preserved.
func (s *Store) RecordAssessment(list ...*Assessment) error {
	s.wr.Lock()
	defer s.wr.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, a := range list {
		if a.SubjectKey == "" || a.Verifier == "" || a.RulesVersion == "" {
			return fmt.Errorf("assessment requires subject, verifier, and rules version")
		}
		if a.Result == "" {
			return fmt.Errorf("assessment requires a result")
		}
		if a.AssessedAtMS == 0 {
			a.AssessedAtMS = time.Now().UnixMilli()
		}
		var exists int
		err := tx.QueryRow(`SELECT 1 FROM assessments
			WHERE subject_key = ? AND verifier = ? AND rules_version = ?
			  AND trust_set_sha = ? AND input_sha = ? AND result = ?`,
			a.SubjectKey, a.Verifier, a.RulesVersion,
			a.TrustSetSHA, a.InputSHA, a.Result).Scan(&exists)
		if err == nil {
			continue
		}
		res, err := tx.Exec(`INSERT INTO assessments
			(subject_key, verifier, rules_version, trust_set_sha, input_sha, result, detail, assessed_at_ms)
			VALUES (?,?,?,?,?,?,?,?)`,
			a.SubjectKey, a.Verifier, a.RulesVersion,
			a.TrustSetSHA, a.InputSHA, a.Result, a.Detail, a.AssessedAtMS)
		if err != nil {
			return err
		}
		a.Seq, _ = res.LastInsertId()
	}
	return tx.Commit()
}

// Assessments returns every recorded verdict about a subject,
// newest first — the audit trail, not a decision.
func (s *Store) Assessments(subjectKey string) ([]*Assessment, error) {
	rows, err := s.db.Query(`SELECT seq, subject_key, verifier, rules_version,
		trust_set_sha, input_sha, result, detail, assessed_at_ms
		FROM assessments WHERE subject_key = ? ORDER BY seq DESC`, subjectKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Assessment
	for rows.Next() {
		a := &Assessment{}
		if err := rows.Scan(&a.Seq, &a.SubjectKey, &a.Verifier, &a.RulesVersion,
			&a.TrustSetSHA, &a.InputSHA, &a.Result, &a.Detail, &a.AssessedAtMS); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// EffectiveAssessment derives the subject's current trust state
// under one policy: which verifier's rules, under which trust set.
// The derivation never edits history — it reads the latest verdict
// of the named verifier for the named rules and reports it as STALE
// when that verdict was produced under a different trust set, so a
// policy change cannot silently launder a rejection into trust.
// Multiple verifiers reporting under the same rules with
// contradictory current results produce CONFLICTED.
func (s *Store) EffectiveAssessment(subjectKey, rulesVersion, trustSetSHA string) (*Assessment, error) {
	// Latest verdict per verifier for these rules — the current
	// opinion of each verifier under its most recent run.
	rows, err := s.db.Query(`SELECT seq, subject_key, verifier, rules_version,
		trust_set_sha, input_sha, result, detail, assessed_at_ms
		FROM assessments a
		WHERE subject_key = ? AND rules_version = ?
		  AND seq = (SELECT MAX(seq) FROM assessments b
		             WHERE b.subject_key = a.subject_key
		               AND b.verifier = a.verifier
		               AND b.rules_version = a.rules_version)
		ORDER BY seq DESC`, subjectKey, rulesVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var latest []*Assessment
	for rows.Next() {
		a := &Assessment{}
		if err := rows.Scan(&a.Seq, &a.SubjectKey, &a.Verifier, &a.RulesVersion,
			&a.TrustSetSHA, &a.InputSHA, &a.Result, &a.Detail, &a.AssessedAtMS); err != nil {
			return nil, err
		}
		latest = append(latest, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(latest) == 0 {
		return &Assessment{
			SubjectKey:   subjectKey,
			RulesVersion: rulesVersion,
			TrustSetSHA:  trustSetSHA,
			Result:       AssessmentUnverified,
		}, nil
	}
	// Any verdict minted under a different trust set is stale under
	// this policy — keep it for audit, never inherit its result.
	var current *Assessment
	results := map[string]int{}
	for _, a := range latest {
		if a.TrustSetSHA != trustSetSHA {
			continue
		}
		if current == nil || a.Seq > current.Seq {
			current = a
		}
		results[a.Result]++
	}
	if len(results) == 0 {
		// Verdicts exist but all under other trust sets — the most
		// recent applicable verifier result is reported stale.
		stale := latest[0]
		for _, a := range latest[1:] {
			if a.Seq > stale.Seq {
				stale = a
			}
		}
		cp := *stale
		cp.Result = AssessmentStale
		cp.Detail = "latest applicable verdict was produced under a different trust set"
		return &cp, nil
	}
	if len(results) > 1 {
		cp := *current
		cp.Result = AssessmentConflicted
		cp.Detail = fmt.Sprintf("verifiers disagree: %s", joinKeys(results))
		return &cp, nil
	}
	return current, nil
}

func joinKeys(m map[string]int) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}
