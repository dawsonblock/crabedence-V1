package history

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sockfile"
)

// CheckpointDomain separates history-checkpoint signatures from every
// other signed record — a witnessed statement about a store's chain
// head, distinct from the custody domain (segment payloads) and the
// evidence domain (terminal enumerations).
const CheckpointDomain = "crabedence-history-checkpoint-v1\x00"

// CheckpointType is the checkpoint record's own identity.
const CheckpointType = "history-checkpoint/v1"

// checkpointFormat is the signing format version — the field vector
// the signature commits to is versioned, so a checkpoint signed under
// one format never verifies as another.
const checkpointFormat = 1

// Checkpoint is an externally witnessed statement about a history
// store's chain head. The store's own chain proves its contents are
// untampered; it cannot prove its tail is still there. The witness's
// signature — held outside the store — is what a rollback of the
// newest events fails against.
type Checkpoint struct {
	RecordType           string `json:"record_type"`
	StoreID              string `json:"store_id"`
	FormatVersion        int    `json:"format_version"`
	Sequence             int64  `json:"sequence"`
	ChainHead            string `json:"chain_head"`
	PrevCheckpointSHA256 string `json:"previous_checkpoint_hash"`
	SourceManifestSHA256 string `json:"source_manifest_hash"`
	WitnessID            string `json:"witness_id"`
	WitnessedAt          string `json:"witnessed_at"`
	PublicKey            string `json:"public_key"`
	Signer               string `json:"signer"`
	Signature            string `json:"signature"`
}

// SigningFields is the versioned, domain-separated vector the
// signature commits to.
func (c *Checkpoint) SigningFields() []string {
	return []string{
		c.RecordType,
		c.StoreID,
		fmt.Sprint(c.FormatVersion),
		fmt.Sprint(c.Sequence),
		c.ChainHead,
		c.PrevCheckpointSHA256,
		c.SourceManifestSHA256,
		c.WitnessID,
		c.WitnessedAt,
		c.PublicKey,
		c.Signer,
	}
}

// StoreID is the stable identity of this history database — assigned
// at creation, carried forever, and bound into every checkpoint so a
// replaced database (however internally valid) cannot inherit the
// witnessed identity.
func (s *Store) StoreID() (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT value FROM store_meta WHERE key = 'store_id'`).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("history store identity: %w", err)
	}
	return id, nil
}

// ChainTail reports the highest committed event: the sequence the
// chain reached and its head digest.
func (s *Store) ChainTail() (seq int64, head string, err error) {
	err = s.db.QueryRow(
		`SELECT seq, sha256 FROM events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &head)
	if err != nil {
		return 0, "", err
	}
	return seq, head, nil
}

// WriteCheckpoint signs a witnessed statement of the store's current
// chain head into dir — the independent custody anchor a rollback of
// the newest events must disagree with. Each checkpoint chains to the
// previous one in dir (previous_checkpoint_hash commits to its raw
// bytes), so the checkpoint series is itself append-only. The write
// is atomic: a crash during creation leaves the last committed
// checkpoint, never a torn one.
//
// The witness must be a key outside this store's administrative
// control — witnessing proves an independent custodian saw this head.
// Witnessing proves what was committed; it cannot prove records that
// were never committed and never witnessed — the guarantee covers
// deletion and replacement of witnessed history, not history nobody
// saw.
func (s *Store) WriteCheckpoint(dir string, witness *evidence.Signer) (*Checkpoint, error) {
	storeID, err := s.StoreID()
	if err != nil {
		return nil, err
	}
	seq, head, err := s.ChainTail()
	if err != nil {
		return nil, fmt.Errorf("history checkpoint: %w", err)
	}
	manifest, err := s.SourceManifestSHA256()
	if err != nil {
		return nil, err
	}
	existing, err := LoadCheckpoints(dir)
	if err != nil {
		return nil, err
	}
	prevSHA := ""
	if len(existing) > 0 {
		prevSHA = existing[len(existing)-1].sha256
	}
	pub := witness.PublicKey()
	cp := &Checkpoint{
		RecordType:           CheckpointType,
		StoreID:              storeID,
		FormatVersion:        checkpointFormat,
		Sequence:             seq,
		ChainHead:            head,
		PrevCheckpointSHA256: prevSHA,
		SourceManifestSHA256: manifest,
		WitnessID:            evidence.Fingerprint(pub),
		WitnessedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey:            base64.StdEncoding.EncodeToString(pub),
		Signer:               evidence.Fingerprint(pub),
	}
	sig, err := witness.SignRecord(CheckpointDomain, cp.SigningFields()...)
	if err != nil {
		return nil, fmt.Errorf("sign history checkpoint: %w", err)
	}
	cp.Signature = sig
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	if err := sockfile.EnsureDir(dir); err != nil {
		return nil, fmt.Errorf("history checkpoint dir: %w", err)
	}
	sum := sha256.Sum256(raw)
	// The filename leads with a write-order ordinal: re-witnessing
	// an unchanged head legitimately repeats a sequence, so order
	// in the witnessed series comes from the ordinal, not the seq.
	name := filepath.Join(dir, fmt.Sprintf("cp-%08d-%08d-%s.json",
		len(existing), seq, hex.EncodeToString(sum[:])[:12]))
	if err := writeAtomicCheckpoint(name, raw); err != nil {
		return nil, err
	}
	return cp, nil
}

// writeAtomicCheckpoint commits the checkpoint file: temp, sync,
// rename, directory sync — a power loss leaves the pre-image or the
// post-image, never a torn checkpoint a verifier might half-load.
func writeAtomicCheckpoint(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return sockfile.FsyncDir(filepath.Dir(path))
}

// checkpointFile is one loaded checkpoint with its raw bytes — the
// chain links commit to bytes, not re-marshaled fields.
type checkpointFile struct {
	cp     *Checkpoint
	raw    []byte
	sha256 string
}

// Checkpoint exposes the loaded checkpoint record for callers that
// iterated a checkpoint dir.
func (cf *checkpointFile) Checkpoint() *Checkpoint { return cf.cp }

// latestCheckpoint loads the most recently written checkpoint in
// dir, or nil when the dir holds none. Malformed files are errors —
// a checkpoint dir is trusted-state storage, and garbage in it is a
// finding, not noise.
func latestCheckpoint(dir string) (*checkpointFile, error) {
	all, err := LoadCheckpoints(dir)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, nil
	}
	return all[len(all)-1], nil
}

// LoadCheckpoints reads every checkpoint in dir in witnessed order —
// filenames lead with the write-order ordinal, so lexical sort IS
// the witnessed series. Orphaned .tmp remnants of interrupted writes
// are skipped — they were never committed.
func LoadCheckpoints(dir string) ([]*checkpointFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read checkpoint dir %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var out []*checkpointFile
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read checkpoint %s: %w", name, err)
		}
		cp := &Checkpoint{}
		if err := json.Unmarshal(raw, cp); err != nil {
			return nil, fmt.Errorf("checkpoint %s malformed: %w", name, err)
		}
		sum := sha256.Sum256(raw)
		out = append(out, &checkpointFile{cp: cp, raw: raw, sha256: hex.EncodeToString(sum[:])})
	}
	return out, nil
}

// VerifyCheckpointFile checks one checkpoint's shape, signature, and
// trust — the same gate any fetched checkpoint file must pass before
// its claims mean anything. trustedWitnesses is the operator's
// approved witness set; an empty set fails closed.
func VerifyCheckpointFile(cp *Checkpoint, trustedWitnesses map[string]bool) error {
	if cp.RecordType != CheckpointType {
		return fmt.Errorf("history checkpoint record_type %q", cp.RecordType)
	}
	if cp.FormatVersion != checkpointFormat {
		return fmt.Errorf("history checkpoint format_version %d unsupported", cp.FormatVersion)
	}
	pub, err := base64.StdEncoding.DecodeString(cp.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("history checkpoint carries an unusable public key")
	}
	if cp.Signer != evidence.Fingerprint(ed25519.PublicKey(pub)) {
		return fmt.Errorf("history checkpoint signer does not match its public key")
	}
	if cp.WitnessID != cp.Signer {
		return fmt.Errorf("history checkpoint witness_id does not match its signer")
	}
	if len(trustedWitnesses) == 0 {
		return fmt.Errorf("no trusted history-checkpoint witnesses configured")
	}
	if !trustedWitnesses[cp.Signer] {
		return fmt.Errorf("history checkpoint witness %s is not trusted", cp.Signer)
	}
	if err := evidence.VerifyRecordSignature(ed25519.PublicKey(pub), CheckpointDomain,
		cp.Signature, cp.SigningFields()...); err != nil {
		return fmt.Errorf("history checkpoint signature invalid: %w", err)
	}
	return nil
}

// VerifyCheckpointChain checks the checkpoint files' own append-only
// property: witnessed sequence never decreases and every
// previous_checkpoint_hash commits to the prior file's raw bytes.
// Returns findings; an empty result means the witnessed series is
// internally consistent.
func VerifyCheckpointChain(cps []*checkpointFile) []string {
	var findings []string
	var prev *checkpointFile
	for _, cf := range cps {
		if prev == nil && cf.cp.PrevCheckpointSHA256 != "" {
			findings = append(findings,
				fmt.Sprintf("checkpoint %d claims a previous link but none exists — the witnessed series was truncated", cf.cp.Sequence))
		}
		if prev != nil {
			if cf.cp.Sequence < prev.cp.Sequence {
				findings = append(findings,
					fmt.Sprintf("checkpoint %d precedes witnessed seq %d — witnessed order violated", cf.cp.Sequence, prev.cp.Sequence))
			}
			if cf.cp.PrevCheckpointSHA256 != prev.sha256 {
				findings = append(findings,
					fmt.Sprintf("checkpoint %d previous link %s does not match the witnessed prior %s — the witnessed series was edited",
						cf.cp.Sequence, cf.cp.PrevCheckpointSHA256, prev.sha256))
			}
		}
		prev = cf
	}
	return findings
}

// VerifyAgainstCheckpoint compares the local store against an
// externally witnessed checkpoint — the rollback detector. The store
// must answer for: identity (same store the witness saw), prefix
// consistency (the witnessed head is still the head at its sequence),
// and completeness (no witnessed event is missing). A store with
// MORE events than the checkpoint witnessed is consistent — the
// checkpoint is merely older; a store with FEWER is a rollback,
// because witnessed events cannot uncommit.
func (s *Store) VerifyAgainstCheckpoint(cp *Checkpoint) []string {
	var findings []string
	storeID, err := s.StoreID()
	if err != nil {
		return append(findings, fmt.Sprintf("history checkpoint verify: %v", err))
	}
	if cp.StoreID != storeID {
		return append(findings, fmt.Sprintf(
			"checkpoint names store %s but this is store %s — a replaced database does not inherit witnessed identity",
			cp.StoreID, storeID))
	}
	if cp.Sequence <= 0 {
		return append(findings, "checkpoint carries no sequence")
	}
	// The witnessed event must still exist and still digest to the
	// witnessed head — rewritten prefix or rollback alike fail here.
	var head string
	err = s.db.QueryRow(`SELECT sha256 FROM events WHERE seq = ?`, cp.Sequence).Scan(&head)
	if err != nil {
		return append(findings, fmt.Sprintf(
			"rollback detected: witnessed event seq %d is absent — the store was rolled back below a witnessed head", cp.Sequence))
	}
	if head != cp.ChainHead {
		return append(findings, fmt.Sprintf(
			"chain mismatch at witnessed seq %d: stored head %s, witnessed %s — prefix rewritten", cp.Sequence, head[:12], cp.ChainHead[:12]))
	}
	return findings
}
