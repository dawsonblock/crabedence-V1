package history

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/openclaw/crabbox/internal/sockfile"
)

// ContentStore is the content-addressed object layer behind memory:
// every observation that derives from source bytes — a conversation
// transcript, a source archive, an agent trace — commits to a digest
// whose bytes are actually held here. Memory links to evidence; the
// store holds it.
type ContentStore struct {
	dir string
}

// OpenContentStore opens (creating if needed) the object dir. Files
// land under objects/<sha256>; names are content, so a stored object
// can never be silently rewritten to other bytes — a put that
// disagrees with the held object is a finding, not an overwrite.
func OpenContentStore(dir string) (*ContentStore, error) {
	if err := sockfile.EnsureDir(filepath.Join(dir, "objects")); err != nil {
		return nil, fmt.Errorf("content store %s: %w", dir, err)
	}
	return &ContentStore{dir: filepath.Join(dir, "objects")}, nil
}

// objectPath resolves a digest to its storage path. A digest that is
// not 64 lowercase hex is refused — content addressing is also the
// confinement: no path escapes the object dir.
func (cs *ContentStore) objectPath(sha string) (string, error) {
	if len(sha) != 64 {
		return "", fmt.Errorf("content digest %q is not sha256", sha)
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return "", fmt.Errorf("content digest %q is not sha256", sha)
	}
	return filepath.Join(cs.dir, sha), nil
}

// Put streams source bytes into the store, returning the digest.
// Writes are atomic (temp, fsync, rename, dir fsync): a crash leaves
// the last committed object, never a torn one. Re-putting identical
// content is idempotent; a held object whose bytes disagree with the
// name is refused — content-addressed storage cannot be a rewrite.
func (cs *ContentStore) Put(r io.Reader) (string, int64, error) {
	tmp, err := os.CreateTemp(cs.dir, ".put-*")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", 0, err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	dst, err := cs.objectPath(sha)
	if err != nil {
		_ = os.Remove(tmpName)
		return "", 0, err
	}
	if held, err := os.ReadFile(dst); err == nil {
		// Already held: the held object must be the same bytes —
		// a digest match that is not a byte match is tampering.
		sum := sha256.Sum256(held)
		if hex.EncodeToString(sum[:]) != sha {
			_ = os.Remove(tmpName)
			return "", 0, fmt.Errorf("content store %s: held bytes disagree with their address", sha)
		}
		_ = os.Remove(tmpName)
		return sha, size, nil
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return "", 0, err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return "", 0, err
	}
	if err := sockfile.FsyncDir(cs.dir); err != nil {
		return "", 0, err
	}
	return sha, size, nil
}

// Has reports whether the digest's bytes are held.
func (cs *ContentStore) Has(sha string) bool {
	p, err := cs.objectPath(sha)
	if err != nil {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// Read opens a held object by digest. The digest is verified on open
// — a caller never receives bytes that fail to prove their name.
func (cs *ContentStore) Read(sha string) ([]byte, error) {
	p, err := cs.objectPath(sha)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != sha {
		return nil, fmt.Errorf("content object %s fails its own address", sha)
	}
	return raw, nil
}

// Verify re-derives every held object's digest from its bytes and
// reports objects that fail their own address or are not regular
// files — storage tampering is a finding, not a silent miss.
func (cs *ContentStore) Verify() []string {
	var findings []string
	entries, err := os.ReadDir(cs.dir)
	if err != nil {
		return []string{fmt.Sprintf("content store: %v", err)}
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".tmp" {
			continue
		}
		p := filepath.Join(cs.dir, e.Name())
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() {
			findings = append(findings, fmt.Sprintf("content object %s is not a regular file", e.Name()))
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			findings = append(findings, fmt.Sprintf("content object %s unreadable: %v", e.Name(), err))
			continue
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != e.Name() {
			findings = append(findings, fmt.Sprintf("content object %s fails its own address", e.Name()))
		}
	}
	return findings
}
