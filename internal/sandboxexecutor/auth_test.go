package sandboxexecutor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePeerAllowlist(t *testing.T) {
	t.Run("valid entries", func(t *testing.T) {
		m, err := ParsePeerAllowlist("501:crabedence, 502 : operator")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got, ok := m.Authorize(501); !ok || got != "crabedence" {
			t.Fatalf("Authorize(501) = %q,%v", got, ok)
		}
		if got, ok := m.Authorize(502); !ok || got != "operator" {
			t.Fatalf("Authorize(502) = %q,%v", got, ok)
		}
	})
	t.Run("empty refuses", func(t *testing.T) {
		if _, err := ParsePeerAllowlist(""); err == nil {
			t.Fatal("empty allowlist must refuse — an executor with no submitter must not run")
		}
	})
	t.Run("malformed entry", func(t *testing.T) {
		for _, raw := range []string{"501", "501:", ":x", "abc:sub", "501:*"} {
			if _, err := ParsePeerAllowlist(raw); err == nil {
				t.Fatalf("%q must refuse", raw)
			}
		}
	})
	t.Run("duplicate uid", func(t *testing.T) {
		if _, err := ParsePeerAllowlist("501:a,501:b"); err == nil {
			t.Fatal("duplicate uid must refuse")
		}
	})
	t.Run("unknown uid denied", func(t *testing.T) {
		m, err := ParsePeerAllowlist("501:a")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m.Authorize(999); ok {
			t.Fatal("unlisted uid must not authorize")
		}
	})
}

func writeTokenFile(t *testing.T, dir, name, content string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSubmissionToken(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid 0600", func(t *testing.T) {
		p := writeTokenFile(t, dir, "tok", "s3cr3t\n", 0o600)
		tok, err := LoadSubmissionToken(p)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if !tok.Verify("s3cr3t") {
			t.Fatal("correct token must verify")
		}
		if tok.Verify("s3cr3tx") || tok.Verify("") {
			t.Fatal("wrong token must not verify")
		}
	})
	t.Run("group/world readable refuses", func(t *testing.T) {
		p := writeTokenFile(t, dir, "tok2", "s3cr3t", 0o640)
		if _, err := LoadSubmissionToken(p); err == nil {
			t.Fatal("a token readable by others is not a secret")
		}
	})
	t.Run("symlink refuses", func(t *testing.T) {
		target := writeTokenFile(t, dir, "real", "s3cr3t", 0o600)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSubmissionToken(link); err == nil {
			t.Fatal("symlinked token must refuse")
		}
	})
	t.Run("empty refuses", func(t *testing.T) {
		p := writeTokenFile(t, dir, "empty", "  \n", 0o600)
		if _, err := LoadSubmissionToken(p); err == nil {
			t.Fatal("empty token must refuse")
		}
	})
	t.Run("missing refuses", func(t *testing.T) {
		if _, err := LoadSubmissionToken(filepath.Join(dir, "nope")); err == nil {
			t.Fatal("missing token must refuse")
		}
	})
	t.Run("nil token allows all", func(t *testing.T) {
		var tok *SubmissionToken
		if !tok.Verify("anything") {
			t.Fatal("nil token disables the token leg")
		}
	})
}

func TestTokenConstantTimeShape(t *testing.T) {
	dir := t.TempDir()
	p := writeTokenFile(t, dir, "tok", "abcdef", 0o600)
	tok, err := LoadSubmissionToken(p)
	if err != nil {
		t.Fatal(err)
	}
	// A prefix or near-miss is not a match.
	for _, bad := range []string{"abcde", "abcdefg", "abcdeg", " abcdef", "abcdef "} {
		if tok.Verify(bad) {
			t.Fatalf("%q must not verify against the token", bad)
		}
	}
}
