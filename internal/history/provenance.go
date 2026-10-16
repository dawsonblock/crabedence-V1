package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// Provenance is the structured origin record every ingested
// observation carries: what it came from, which bytes it commits to,
// who imported it, and — where a name was asserted rather than
// detected — both the claim and the finding. A filename is never
// authoritative identity: an archive called RC7.1 can contain an
// RC7.3 tree, and memory keeps both statements separately.
type Provenance struct {
	// SourceKind names the importer family: git, ledger, evidence,
	// custody, teststream, document, chat, archive, agent-trace…
	SourceKind string `json:"source_kind"`
	// SourceIdentity is the stable identity of the source object —
	// repository path+remote, ledger file, evidence dir — not a
	// display name.
	SourceIdentity string `json:"source_identity"`
	// ContentSHA256 is the digest of the exact source bytes the
	// observation was derived from — the link to the content store.
	ContentSHA256 string `json:"content_sha256,omitempty"`
	// Importer names the ingester version that produced the record —
	// the same source re-read by a fixed importer is a new
	// observation, not a contradiction.
	Importer string `json:"importer"`
	// ImportedAtMS is when the observation was taken — the evidence's
	// own as-of time, distinct from occurred_at (the event's time).
	ImportedAtMS int64 `json:"imported_at_ms"`
	// SuppliedName is an asserted identity that arrived with the
	// source (filename, manifest label) — recorded, never trusted.
	SuppliedName string `json:"supplied_name,omitempty"`
	// DetectedName is the identity the importer found in the content
	// itself — recorded alongside the claim when they disagree.
	DetectedName string `json:"detected_name,omitempty"`
}

// manifestDomain separates the source-manifest digest from every
// other SHA-256 construction — a manifest digest means "this set of
// sources at these heads", nothing else.
const manifestDomain = "crabedence.history-source-manifest.v1\x00"

// SourceManifestSHA256 commits to the store's applicable source
// inventory: every distinct ingest source and how far the chain had
// read from it. Two stores with the same manifest consumed the same
// sources to the same point — the checkpoint binds it so a replayed
// or partial history cannot impersonate the witnessed inventory.
func (s *Store) SourceManifestSHA256() (string, error) {
	rows, err := s.db.Query(
		`SELECT source, MAX(seq), COUNT(*) FROM events GROUP BY source ORDER BY source`)
	if err != nil {
		return "", fmt.Errorf("source manifest: %w", err)
	}
	defer rows.Close()
	type entry struct {
		source string
		maxSeq int64
		count  int
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.source, &e.maxSeq, &e.count); err != nil {
			return "", err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].source < entries[j].source })
	var b bytes.Buffer
	b.WriteString(manifestDomain)
	var l [4]byte
	put := func(s string) {
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b.Write(l[:])
		b.WriteString(s)
	}
	putInt := func(v int64) {
		var i [8]byte
		binary.BigEndian.PutUint64(i[:], uint64(v))
		b.Write(i[:])
	}
	for _, e := range entries {
		put(e.source)
		putInt(e.maxSeq)
		putInt(int64(e.count))
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}
