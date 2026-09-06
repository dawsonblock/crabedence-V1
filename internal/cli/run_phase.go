package cli

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	failureTailLines        = 40
	failureTailLineBytes    = 16 * 1024
	phaseMarkerPendingBytes = 4 * 1024
)

type streamTailBuffer struct {
	max     int
	lines   []string
	pending string
}

func newStreamTailBuffer(max int) *streamTailBuffer {
	if max <= 0 {
		max = failureTailLines
	}
	return &streamTailBuffer{max: max}
}

func (b *streamTailBuffer) Write(p []byte) (int, error) {
	text := b.pending + string(p)
	parts := strings.SplitAfter(text, "\n")
	b.pending = ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		if strings.HasSuffix(part, "\n") {
			b.append(truncateFailureTailLine(strings.TrimRight(part, "\r\n")))
			continue
		}
		b.pending = truncateFailureTailLine(part)
	}
	return len(p), nil
}

func (b *streamTailBuffer) Lines() []string {
	lines := append([]string(nil), b.lines...)
	if b.pending != "" {
		lines = append(lines, b.pending)
	}
	if len(lines) > b.max {
		lines = lines[len(lines)-b.max:]
	}
	return lines
}

func (b *streamTailBuffer) append(line string) {
	b.lines = append(b.lines, line)
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

func truncateFailureTailLine(line string) string {
	if len(line) <= failureTailLineBytes {
		return line
	}
	return "[truncated] " + line[len(line)-failureTailLineBytes:]
}

type commandPhaseTracker struct {
	mu           sync.Mutex
	current      string
	currentStart time.Time
	phases       []timingPhase
}

type CommandPhaseTracker = commandPhaseTracker

func newCommandPhaseTracker(start time.Time) *commandPhaseTracker {
	return &commandPhaseTracker{current: "user-command", currentStart: start}
}

func NewCommandPhaseTracker(start time.Time) *CommandPhaseTracker {
	return newCommandPhaseTracker(start)
}

func FinishCommandPhaseTracker(tracker *CommandPhaseTracker, at time.Time) []TimingPhase {
	if tracker == nil {
		return nil
	}
	return tracker.Finish(at)
}

func (t *commandPhaseTracker) StartPhase(name string, at time.Time) {
	name = sanitizePhaseName(name)
	if name == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finishCurrentLocked(at)
	t.current = name
	t.currentStart = at
}

func (t *commandPhaseTracker) Finish(at time.Time) []timingPhase {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finishCurrentLocked(at)
	out := make([]timingPhase, len(t.phases))
	copy(out, t.phases)
	return out
}

func (t *commandPhaseTracker) finishCurrentLocked(at time.Time) {
	if t.current == "" || t.currentStart.IsZero() {
		return
	}
	if at.Before(t.currentStart) {
		at = t.currentStart
	}
	t.phases = append(t.phases, timingPhase{Name: t.current, Ms: at.Sub(t.currentStart).Milliseconds()})
	t.current = ""
	t.currentStart = time.Time{}
}

type phaseMarkerWriter struct {
	tracker *commandPhaseTracker
	pending string
}

type PhaseMarkerWriter = phaseMarkerWriter

func NewPhaseMarkerWriter(tracker *CommandPhaseTracker) *PhaseMarkerWriter {
	return &phaseMarkerWriter{tracker: tracker}
}

func (w *phaseMarkerWriter) Write(p []byte) (int, error) {
	if w == nil || w.tracker == nil {
		return len(p), nil
	}
	text := w.pending + string(p)
	for {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			break
		}
		w.observeLine(text[:i])
		text = text[i+1:]
	}
	w.pending = truncatePhaseMarkerPending(text)
	return len(p), nil
}

func (w *phaseMarkerWriter) Flush() {
	if w != nil && w.pending != "" {
		w.observeLine(w.pending)
		w.pending = ""
	}
}

func (w *phaseMarkerWriter) observeLine(line string) {
	if name, ok := phaseNameFromLine(line); ok {
		w.tracker.StartPhase(name, time.Now())
	}
}

func truncatePhaseMarkerPending(line string) string {
	if len(line) <= phaseMarkerPendingBytes {
		return line
	}
	return line[len(line)-phaseMarkerPendingBytes:]
}

func phaseNameFromLine(line string) (string, bool) {
	const prefix = "CRABBOX_PHASE:"
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	name := sanitizePhaseName(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
	return name, name != ""
}

func sanitizePhaseName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 80 {
		name = name[:80]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

func formatCommandPhaseTimings(phases []timingPhase) string {
	parts := make([]string, 0, len(phases))
	for _, phase := range phases {
		if phase.Name == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s", phase.Name, time.Duration(phase.Ms)*time.Millisecond))
	}
	return strings.Join(parts, ",")
}
