// Command nemo-archive-extract unpacks a NEMO-CONTROL distribution archive
// for qualification.
//
// `tar -x` on an untrusted archive is not a boundary: member names can be
// absolute or carry `..` and reach outside the extraction directory, links can
// point anywhere, and device/fifo members are writable surprises. The
// extractor makes the archive prove itself instead — a preflight pass accepts
// only directory and regular-file members whose cleaned names stay inside the
// destination, refuses duplicate targets and every other node type, and only
// then writes, so a rejected archive leaves nothing extracted behind.
//
// Usage:
//
//	go run ./cmd/nemo-archive-extract -archive dist/nemo-control.tar.gz -dest /tmp/unpack
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	archive := flag.String("archive", "", "the packed distribution archive (tar or tar.gz)")
	dest := flag.String("dest", "", "the directory to extract into (created, must be empty)")
	flag.Parse()
	if *archive == "" || *dest == "" {
		fmt.Fprintln(os.Stderr, "nemo-archive-extract: -archive and -dest are required")
		os.Exit(2)
	}
	if err := extractArchive(*archive, *dest); err != nil {
		fmt.Fprintf(os.Stderr, "nemo-archive-extract: %v\n", err)
		os.Exit(1)
	}
}

// openMembers opens the archive — gzip when the stream's magic says so, plain
// tar otherwise, so the same verifier path accepts both packings.
func openMembers(path string) (*tar.Reader, io.Closer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	magic := make([]byte, 2)
	if _, err := io.ReadFull(file, magic); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("reading the archive magic: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, nil, err
	}
	if magic[0] == 0x1f && magic[1] == 0x8b {
		unzip, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("the archive is not a readable gzip stream: %w", err)
		}
		return tar.NewReader(unzip), struct{ io.Closer }{multiCloser{unzip, file}}, nil
	}
	return tar.NewReader(file), file, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var first error
	for _, closer := range m {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// memberTarget resolves a member name to its path under dest — or refuses it.
// The checks are the containment contract: no empty name, no NUL, nothing
// absolute, no `..` component, and the joined path must stay inside dest.
func memberTarget(dest, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("a member carries no name")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("member %q: NUL in the name", name)
	}
	rel := filepath.FromSlash(name)
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("member %q: absolute paths cannot be extracted", name)
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return "", fmt.Errorf("member %q: '..' escapes the extraction directory", name)
		}
	}
	target := filepath.Join(dest, rel)
	cleanDest := filepath.Clean(dest) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(target)+string(filepath.Separator), cleanDest) {
		return "", fmt.Errorf("member %q: resolves outside the extraction directory", name)
	}
	return target, nil
}

// member is one preflighted archive entry.
type member struct {
	header *tar.Header
	target string
}

// preflightMembers reads the whole archive without writing a byte and accepts
// only what the distribution is allowed to carry: directories and regular
// files with in-directory names, each target used once, and no member nested
// under a file. Everything else — links, devices, fifos, escapes — refuses the
// archive before extraction begins.
func preflightMembers(reader *tar.Reader, dest string) ([]member, error) {
	var members []member
	seen := make(map[string]bool)
	files := make(map[string]bool)
	dirs := make(map[string]bool)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the archive is not a readable tar stream: %w", err)
		}
		target, err := memberTarget(dest, header.Name)
		if err != nil {
			return nil, err
		}
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg, tar.TypeRegA:
		default:
			return nil, fmt.Errorf("member %q: only directories and regular files ship (typeflag %d)", header.Name, header.Typeflag)
		}
		if seen[target] {
			return nil, fmt.Errorf("member %q: a second entry for the same path would overwrite the first", header.Name)
		}
		seen[target] = true
		// No earlier file member may sit on this member's path — a file cannot
		// be a directory. Walking to dest suffices: the target is inside it.
		cleanDest := filepath.Clean(dest)
		for parent := filepath.Dir(target); strings.HasPrefix(parent, cleanDest+string(filepath.Separator)); parent = filepath.Dir(parent) {
			if files[parent] {
				return nil, fmt.Errorf("member %q: nested under %q, which a previous member claims as a file", header.Name, parent)
			}
			// Every member makes its ancestors directories — whether or not
			// the archive spells them explicitly — so a later member may not
			// claim any of them as a file.
			dirs[parent] = true
		}
		if header.Typeflag == tar.TypeDir {
			dirs[target] = true
		} else {
			if dirs[target] {
				return nil, fmt.Errorf("member %q: claimed as a file, but an earlier member nested beneath it already claimed it as a directory", header.Name)
			}
			files[target] = true
		}
		headerCopy := *header
		members = append(members, member{header: &headerCopy, target: target})
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("the archive carries no members")
	}
	return members, nil
}

func extractArchive(archivePath, dest string) error {
	// The destination is a scratch this run owns: it must not exist yet or be
	// an empty directory, so extraction can never overwrite a live tree.
	if info, err := os.Stat(dest); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("destination %s exists and is not a directory", dest)
		}
		entries, err := os.ReadDir(dest)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("destination %s is not empty — extraction requires a scratch it owns", dest)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return err
		}
	} else {
		return err
	}

	reader, closer, err := openMembers(archivePath)
	if err != nil {
		return err
	}
	members, err := preflightMembers(reader, dest)
	closer.Close()
	if err != nil {
		return err
	}

	// Preflight proved the archive safe as a whole; the write pass never
	// touches a path outside dest because every target came from memberTarget.
	reader, closer, err = openMembers(archivePath)
	if err != nil {
		return err
	}
	defer closer.Close()
	memberIndex := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("re-reading the archive: %w", err)
		}
		if memberIndex >= len(members) {
			return fmt.Errorf("the archive grew between passes at %q", header.Name)
		}
		entry := members[memberIndex]
		memberIndex++
		if entry.header.Name != header.Name || entry.header.Typeflag != header.Typeflag {
			return fmt.Errorf("the archive changed between passes at %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(entry.target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(entry.target), 0o755); err != nil {
				return err
			}
			mode := header.FileInfo().Mode().Perm() & 0o777
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(entry.target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, reader); err != nil {
				out.Close()
				return fmt.Errorf("extracting %q: %w", header.Name, err)
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
	if memberIndex != len(members) {
		return fmt.Errorf("the archive shrank between passes: %d of %d members written", memberIndex, len(members))
	}
	fmt.Printf("extracted %d members from %s to %s\n", len(members), archivePath, dest)
	return nil
}
