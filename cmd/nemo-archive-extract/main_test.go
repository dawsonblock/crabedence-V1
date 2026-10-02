package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testMember is one archive entry: typeflag, name, and content for files.
type testMember struct {
	typeflag byte
	name     string
	linkname string
	content  string
}

// writeArchive packs members into a .tar.gz the extractor can read.
func writeArchive(t *testing.T, members []testMember) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dist.tar.gz")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(out)
	writer := tar.NewWriter(gz)
	for _, m := range members {
		header := &tar.Header{Name: m.name, Typeflag: m.typeflag, Mode: 0o644, Linkname: m.linkname}
		if m.typeflag == tar.TypeReg {
			header.Size = int64(len(m.content))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if m.typeflag == tar.TypeReg {
			if _, err := writer.Write([]byte(m.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, closer := range []io.Closer{writer, gz, out} {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func destDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "unpack")
}

func TestExtractsABenignDistribution(t *testing.T) {
	archive := writeArchive(t, []testMember{
		{tar.TypeDir, "nemo-control/", "", ""},
		{tar.TypeReg, "nemo-control/bin/crabbox", "", "cli-bytes"},
		{tar.TypeReg, "nemo-control/manifests/component-manifest.json", "", "{}"},
	})
	dest := destDir(t)
	if err := extractArchive(archive, dest); err != nil {
		t.Fatalf("a benign archive must extract: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "nemo-control", "bin", "crabbox"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "cli-bytes" {
		t.Fatalf("extracted content: %q", content)
	}
}

func TestRejectsEscapesAndUnsafeMembers(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside-target")
	cases := []struct {
		name    string
		member  testMember
		wantErr string
	}{
		{"parent traversal", testMember{tar.TypeReg, "../escape.txt", "", "x"}, "'..' escapes"},
		{"nested traversal", testMember{tar.TypeReg, "dist/../../../etc/passwd", "", "x"}, "'..' escapes"},
		{"absolute path", testMember{tar.TypeReg, "/etc/pwned", "", "x"}, "absolute paths"},
		{"hardlink", testMember{tar.TypeLink, "dist/bin/crabbox", "/bin/sh", ""}, "only directories and regular files"},
		{"symlink member", testMember{tar.TypeSymlink, "dist/linked", "outside", ""}, "only directories and regular files"},
		{"fifo", testMember{tar.TypeFifo, "dist/pipe", "", ""}, "only directories and regular files"},
		{"device", testMember{tar.TypeBlock, "dist/dev0", "", ""}, "only directories and regular files"},
		{"duplicate member", testMember{tar.TypeReg, "a.txt", "", "x"}, "overwrite"},
		{"file as directory", testMember{tar.TypeReg, "f/inner.txt", "", "x"}, "nested under"},
		{"directory as file", testMember{tar.TypeReg, "g", "", "x"}, "claimed as a file"},
		{"explicit dir over file", testMember{tar.TypeDir, "h", "", ""}, "overwrite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			members := []testMember{{tar.TypeReg, "ok.txt", "", "fine"}}
			switch tc.name {
			case "duplicate member":
				members = append(members, testMember{tar.TypeReg, "a.txt", "", "first"}, tc.member)
			case "file as directory":
				members = append(members, testMember{tar.TypeReg, "f", "", "file"}, tc.member)
			case "directory as file":
				// The reverse order: a member nested under g is seen first,
				// so g is a directory by the time the file member claims it.
				members = append(members, testMember{tar.TypeReg, "g/inner.txt", "", "nested"}, tc.member)
			case "explicit dir over file":
				// The file lands first; the later TypeDir member targets the
				// same path and must refuse before extraction.
				members = append(members, testMember{tar.TypeReg, "h", "", "file"}, tc.member)
			default:
				members = append(members, tc.member)
			}
			dest := destDir(t)
			err := extractArchive(writeArchive(t, members), dest)
			if err == nil {
				t.Fatal("an unsafe member must refuse the whole archive")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
			// A refused archive leaves nothing extracted — not even the benign
			// member written before it would be seen.
			entries, readErr := os.ReadDir(dest)
			if readErr == nil && len(entries) != 0 {
				t.Fatalf("a refused archive must not extract partially: %v", entries)
			}
		})
	}
	if err := extractArchive(writeArchive(t, []testMember{
		{tar.TypeReg, "../../escape.txt", "", "x"},
	}), destDir(t)); err == nil {
		t.Fatal("an archive that escapes must fail")
	}
	// Nothing lands outside even in the failure cases above.
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatal("an unsafe archive must never write outside the destination")
	}
}

func TestRejectsEmptyAndNonTarInput(t *testing.T) {
	empty := writeArchive(t, nil)
	if err := extractArchive(empty, destDir(t)); err == nil ||
		!strings.Contains(err.Error(), "no members") {
		t.Fatal("an empty archive must fail")
	}
	notTar := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(notTar, []byte("this is not a tar stream at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(notTar, destDir(t)); err == nil {
		t.Fatal("a non-tar stream must fail")
	}
}

func TestRefusesAnOccupiedDestination(t *testing.T) {
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "live.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := writeArchive(t, []testMember{{tar.TypeReg, "ok.txt", "", "x"}})
	err := extractArchive(archive, dest)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("extraction must refuse a destination it does not own: %v", err)
	}
}

func TestExtractsPlainTarAsWellAsGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dist.tar")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(out)
	content := "plain tar bytes"
	if err := writer.WriteHeader(&tar.Header{Name: "f.txt", Typeflag: tar.TypeReg, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	dest := destDir(t)
	if err := extractArchive(path, dest); err != nil {
		t.Fatalf("a plain tar must extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "f.txt"))
	if err != nil || string(got) != content {
		t.Fatalf("extracted %q, %v", got, err)
	}
}

func TestSetuidModeIsNotPropagated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.tar")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(out)
	content := "x"
	// A mode with setuid/setgid/sticky must not survive extraction.
	if err := writer.WriteHeader(&tar.Header{Name: "suid", Typeflag: tar.TypeReg, Size: 1, Mode: 0o4755}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	dest := destDir(t)
	if err := extractArchive(path, dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "suid"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o, want 0755 with setuid stripped", info.Mode().Perm())
	}
}
