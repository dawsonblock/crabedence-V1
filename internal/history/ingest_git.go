package history

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// gitRecord is the canonical payload a code_change event commits to.
type gitRecord struct {
	Commit     string          `json:"commit"`
	Parents    []string        `json:"parents"`
	Author     string          `json:"author"`
	Email      string          `json:"email"`
	UnixTime   int64           `json:"unix_time"`
	Subject    string          `json:"subject"`
	Files      []gitRecordFile `json:"files"`
	Merge      bool            `json:"merge"`
	RootCommit bool            `json:"root_commit"`
}

type gitRecordFile struct {
	Path string `json:"path"`
	// Adds/Dels are -1 for binary files, which git reports as '-'.
	Adds int64 `json:"adds"`
	Dels int64 `json:"dels"`
}

// IngestGit records a repository's commit history as code_change
// events. rangeSpec is a git revision range ("main", "v1.0..HEAD",
// "--all"); empty means HEAD's whole first-parent-visible history.
// Each event is deduped on git:<repo>:<commit>, so incremental
// re-ingestion appends only new commits.
//
// The event is a record of the commit's own data plus its diffstat —
// file identities and line deltas, not file contents — so memory
// stays useful without duplicating the repository.
func (s *Store) IngestGit(ctx context.Context, repoDir string, rangeSpec string) (int, error) {
	abs, err := filepath.Abs(repoDir)
	if err != nil {
		return 0, err
	}
	// The repository's own identity in memory: its root directory
	// path as ingested. Two checkouts of the same repo produce
	// distinct correlation keys — their histories are distinct
	// development records.
	args := []string{"-C", abs, "log", "--format=%x1e%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s", "--numstat", "-z"}
	if rangeSpec != "" {
		args = append(args, rangeSpec)
	}
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return 0, fmt.Errorf("git log %s: %w", abs, err)
	}
	var events []*Event
	for _, raw := range strings.Split(string(out), "\x1e") {
		raw = strings.TrimLeft(raw, "\x00\n")
		if raw == "" {
			continue
		}
		rec, err := parseGitRecord(raw)
		if err != nil {
			return 0, fmt.Errorf("git log %s: %w", abs, err)
		}
		payload, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		events = append(events, &Event{
			DedupeKey:   "git:" + abs + ":" + rec.Commit,
			Kind:        KindCodeChange,
			Subject:     rec.Commit,
			Correlation: abs,
			Source:      "git",
			OccurredAt:  rec.UnixTime * 1000,
			Payload:     payload,
		})
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// parseGitRecord decodes one --numstat/-z record: the format header
// line, a NUL, then NUL-separated "adds\tdels\tpath" file lines.
func parseGitRecord(raw string) (*gitRecord, error) {
	head, rest, _ := strings.Cut(raw, "\x00")
	fields := strings.Split(head, "\x1f")
	if len(fields) != 6 {
		return nil, fmt.Errorf("malformed commit record: %q", head)
	}
	unixTime, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed commit time %q", fields[4])
	}
	rec := &gitRecord{
		Commit:   fields[0],
		Author:   fields[2],
		Email:    fields[3],
		UnixTime: unixTime,
		Subject:  fields[5],
	}
	if fields[1] == "" {
		rec.RootCommit = true
	} else {
		rec.Parents = strings.Fields(fields[1])
		rec.Merge = len(rec.Parents) > 1
	}
	statLines := strings.Split(rest, "\x00")
	for i := 0; i < len(statLines); i++ {
		// git emits a newline separator after each NUL in -z mode —
		// strip it, but preserve spaces (paths can carry them).
		f := strings.TrimLeft(statLines[i], "\r\n")
		if f == "" {
			continue
		}
		parts := strings.SplitN(f, "\t", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("malformed numstat line %q", f)
		}
		path := parts[2]
		if path == "" {
			// A rename/copy under -z: the status field ends at the
			// tab and the two paths follow as separate NUL fields.
			if i+2 >= len(statLines) {
				return nil, fmt.Errorf("truncated rename numstat line %q", f)
			}
			i++
			path = statLines[i+1] // record the destination path
			i++
		}
		rec.Files = append(rec.Files, gitRecordFile{
			Path: path,
			Adds: parseNumstatField(parts[0]),
			Dels: parseNumstatField(parts[1]),
		})
	}
	return rec, nil
}

// parseNumstatField maps git's numstat field to a number; '-' (binary
// files) becomes -1 rather than a lie about line counts.
func parseNumstatField(s string) int64 {
	if s == "-" {
		return -1
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
