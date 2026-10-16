package history

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// archiveRecord is the canonical payload an archive event commits
// to. The supplied filename and the detected identity are recorded
// side by side: a filename is a claim attached to the container,
// never authoritative identity — an archive called RC7.1 that
// contains an RC7.3 tree is recorded as exactly that disagreement.
type archiveRecord struct {
	SuppliedName    string `json:"supplied_name"`
	SuppliedVersion string `json:"supplied_version,omitempty"`
	DetectedVersion string `json:"detected_version,omitempty"`
	DetectedSource  string `json:"detected_source,omitempty"` // file the detection came from
	VersionConflict bool   `json:"version_conflict"`
	Format          string `json:"format"` // zip | tar | tar.gz
	MemberCount     int    `json:"member_count"`
	ManifestSHA256  string `json:"manifest_sha256"` // digest of the member manifest
	ContentSHA256   string `json:"content_sha256"`  // archive bytes in the content store
	TotalBytes      int64  `json:"total_bytes"`
	TopDirs         int    `json:"top_dirs"`
}

// versionInName pulls a version-looking token out of a supplied
// filename — used only to compare against the detected identity, so
// a mismatch can be recorded as a conflict rather than resolved.
// Pre-release tags take dotted NUMERICS only (rc.7.1) — file
// extensions (.zip, .json) are not version components.
var versionInName = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?(?:-[a-z]+(?:\.\d+)*)?)`)

// IngestArchive records one source archive file (zip, tar, tar.gz):
// the bytes are committed to the content store, the member manifest
// digested, and the project identity detected from manifest files
// INSIDE the archive (VERSION, package.json, go.mod, Cargo.toml) —
// never inferred from the filename. A supplied-version/detection
// mismatch is recorded as version_conflict: memory keeps the
// disagreement instead of silently choosing a side.
func (s *Store) IngestArchive(path string, cs *ContentStore) (int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	sha, size, err := cs.Put(fh)
	fh.Close()
	if err != nil {
		return 0, fmt.Errorf("store archive %s: %w", path, err)
	}
	raw, err := cs.Read(sha)
	if err != nil {
		return 0, err
	}
	rec, err := inspectArchive(raw)
	if err != nil {
		return 0, fmt.Errorf("archive %s: %w", path, err)
	}
	base := filepath.Base(path)
	rec.SuppliedName = base
	if m := versionInName.FindString(base); m != "" {
		rec.SuppliedVersion = m
		if rec.DetectedVersion != "" && rec.DetectedVersion != m &&
			!strings.Contains(rec.DetectedVersion, m) && !strings.Contains(m, rec.DetectedVersion) {
			rec.VersionConflict = true
		}
	}
	rec.ContentSHA256 = sha
	rec.TotalBytes = size
	payload, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(payload)
	subject := base
	if rec.DetectedVersion != "" {
		subject = rec.DetectedVersion + "@" + base
	}
	appended, err := s.Append(&Event{
		DedupeKey:   "archive:" + hex.EncodeToString(sum[:]),
		Kind:        KindArchive,
		Subject:     subject,
		Correlation: sha,
		Source:      "archive:" + path,
		OccurredAt:  fileModMS(path),
		Payload:     payload,
	})
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// inspectArchive digests the member manifest and detects the
// project's declared version from the members themselves.
func inspectArchive(raw []byte) (*archiveRecord, error) {
	rec := &archiveRecord{}
	var members []*archiveMember
	if zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw))); err == nil {
		rec.Format = "zip"
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
			rc.Close()
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(data)
			m := &archiveMember{Name: f.Name, Size: int64(len(data)), SHA: hex.EncodeToString(sum[:])}
			members = append(members, m)
			rec.detectVersion(f.Name, data)
		}
	} else {
		var tr io.Reader = bytes.NewReader(raw)
		if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
			gz, err := gzip.NewReader(tr)
			if err != nil {
				return nil, fmt.Errorf("unrecognized archive: not zip, tar, or tar.gz")
			}
			defer gz.Close()
			tr = gz
			rec.Format = "tar.gz"
		} else {
			rec.Format = "tar"
		}
		rd := tar.NewReader(tr)
		for {
			h, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("unrecognized archive: %w", err)
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(rd, 1<<20))
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(data)
			m := &archiveMember{Name: h.Name, Size: h.Size, SHA: hex.EncodeToString(sum[:])}
			members = append(members, m)
			rec.detectVersion(h.Name, data)
		}
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("archive holds no files")
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	manifest, _ := json.Marshal(members)
	sum := sha256.Sum256(manifest)
	rec.ManifestSHA256 = hex.EncodeToString(sum[:])
	rec.MemberCount = len(members)
	top := map[string]bool{}
	for _, m := range members {
		if i := strings.Index(m.Name, "/"); i > 0 {
			top[m.Name[:i]] = true
		}
	}
	rec.TopDirs = len(top)
	return rec, nil
}

// archiveMember is one file's manifest row — name, size, digest.
type archiveMember struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	SHA  string `json:"sha256"`
}

// detectVersion reads the project's own declaration files — the
// identity the content claims for itself.
func (r *archiveRecord) detectVersion(name string, data []byte) {
	base := filepath.Base(name)
	switch base {
	case "VERSION":
		if v := strings.TrimSpace(string(data)); v != "" && r.DetectedVersion == "" {
			r.DetectedVersion = v
			r.DetectedSource = name
		}
	case "package.json":
		var pkg struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		}
		if json.Unmarshal(data, &pkg) == nil && pkg.Version != "" && r.DetectedVersion == "" {
			r.DetectedVersion = pkg.Version
			r.DetectedSource = name
		}
	case "Cargo.toml":
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "version") {
				if i := strings.Index(line, "\""); i >= 0 {
					v := strings.Trim(line[i+1:], ` "`)
					if j := strings.Index(v, "\""); j > 0 {
						v = v[:j]
					}
					if v != "" && r.DetectedVersion == "" {
						r.DetectedVersion = v
						r.DetectedSource = name
					}
				}
				break
			}
		}
	}
}

// fileModMS is a file's mtime in unix ms — the archive's own time.
func fileModMS(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.ModTime().UnixMilli()
}
