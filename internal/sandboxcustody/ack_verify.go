package sandboxcustody

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/openclaw/crabbox/internal/evidence"
)

// AckBinding is what the requester knows an acknowledgement must
// commit to — the exact segment identity it asked the witness to
// hold. An acknowledgement that binds anything else is evidence for
// a different custody event and answers this request not at all.
type AckBinding struct {
	SegmentSeq       int64
	FirstTerminalSeq int64
	LastTerminalSeq  int64
	RowCount         int
	PayloadSHA256    string
	RequestCreatedAt int64
	// DeploymentID is the deployment scope the request committed.
	// When set, only a v3 acknowledgement signing that exact scope
	// satisfies the binding — a v1/v2 record (no signed deployment)
	// or a record minted for another deployment is evidence for a
	// different custody event.
	DeploymentID string
}

// BindingFor derives the binding a verifier expects from the request
// it sent — the acknowledgement is checked against the ask, not
// against what the response claims the ask was.
func BindingFor(req *WitnessRequest) *AckBinding {
	return &AckBinding{
		SegmentSeq:       req.SegmentSeq,
		FirstTerminalSeq: req.FirstTerminalSeq,
		LastTerminalSeq:  req.LastTerminalSeq,
		RowCount:         req.RowCount,
		PayloadSHA256:    req.SHA256,
		RequestCreatedAt: req.CreatedAt,
		DeploymentID:     req.DeploymentID,
	}
}

// VerifyWitnessAck independently verifies a custody acknowledgement:
// the record must be a known version, bind the exact segment identity
// requested, carry a self-consistent signer identity, be signed under
// the versioned domain-separated vector by a witness the trust root
// approves — and nothing else counts. A nil or empty trust root fails
// closed: an unpinned witness is a self-declared identity.
//
// Verification order is deliberate: shape before identity before
// signature, so a refusal names the cheapest dishonesty first and a
// forged record cannot make the verifier do a signature's work on its
// behalf.
func VerifyWitnessAck(ack *AckRecord, want *AckBinding, trust *TrustRoot) error {
	if ack == nil {
		return fmt.Errorf("custody acknowledgement absent — a self-declared success is not evidence")
	}
	if ack.RecordType != AckRecordTypeV1 && ack.RecordType != AckRecordTypeV2 &&
		ack.RecordType != AckRecordTypeV3 {
		return fmt.Errorf("custody ack record_type %q unsupported", ack.RecordType)
	}
	if want != nil {
		if ack.SegmentSeq != want.SegmentSeq ||
			ack.FirstTerminalSeq != want.FirstTerminalSeq ||
			ack.LastTerminalSeq != want.LastTerminalSeq ||
			ack.RowCount != want.RowCount ||
			ack.PayloadSHA256 != want.PayloadSHA256 {
			return fmt.Errorf("custody ack binds segment %d digest %s — not the requested segment %d digest %s",
				ack.SegmentSeq, ack.PayloadSHA256, want.SegmentSeq, want.PayloadSHA256)
		}
		// v2 binds the request instance; a replayed acknowledgement
		// minted for another request fails here even when every
		// segment field coincidentally matches.
		if (ack.RecordType == AckRecordTypeV2 || ack.RecordType == AckRecordTypeV3) &&
			ack.RequestCreatedAt != want.RequestCreatedAt {
			return fmt.Errorf("custody ack binds a different request instance (created_at %d, want %d)",
				ack.RequestCreatedAt, want.RequestCreatedAt)
		}
		// A deployment-scoped binding is satisfied only by a v3
		// record signing that exact scope: v1/v2 records carry no
		// signed deployment field at all, so an acknowledgement from
		// another ledger — or an unscoped request — can never be
		// replayed as this deployment's custody.
		if want.DeploymentID != "" &&
			(ack.RecordType != AckRecordTypeV3 || ack.DeploymentID != want.DeploymentID) {
			return fmt.Errorf("custody ack binds deployment %q — not the requesting deployment %q",
				ack.DeploymentID, want.DeploymentID)
		}
	}
	pub, err := base64.StdEncoding.DecodeString(ack.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("custody ack carries an unusable public key")
	}
	key := ed25519.PublicKey(pub)
	if ack.Signer != evidence.Fingerprint(key) {
		return fmt.Errorf("custody ack signer %s does not match its public key", ack.Signer)
	}
	if trust.Empty() {
		return fmt.Errorf("no trusted custody witness configured — refusing self-declared custody")
	}
	if !trust.Approve(ack.Signer, key) {
		return fmt.Errorf("custody ack signer %s is not an approved witness", ack.Signer)
	}
	fields, err := ack.SigningFields()
	if err != nil {
		return err
	}
	if err := evidence.VerifyRecordSignature(key, WitnessDomain, ack.Signature, fields...); err != nil {
		return fmt.Errorf("custody ack signature invalid: %w", err)
	}
	return nil
}
