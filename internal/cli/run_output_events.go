package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	runEventOutputChunkBytes = 16 * 1024
	runEventOutputMaxBytes   = 64 * 1024
	runEventOutputQueueSize  = 32
	runEventOutputPostWait   = 2 * time.Second
)

type runOutputEventQueue struct {
	coord           *CoordinatorClient
	runID           string
	onError         func(string, error) bool
	outputMu        sync.Mutex
	outputBytes     int
	outputTruncated bool
	queueOnce       sync.Once
	closeOnce       sync.Once
	queueMu         sync.Mutex
	queueClosed     bool
	disabled        bool
	events          chan CoordinatorRunEventInput
	wg              sync.WaitGroup
}

func newRunOutputEventQueue(coord *CoordinatorClient, runID string, onError func(string, error) bool) *runOutputEventQueue {
	return &runOutputEventQueue{
		coord:   coord,
		runID:   runID,
		onError: onError,
	}
}

func (q *runOutputEventQueue) Closed() bool {
	if q == nil {
		return true
	}
	q.outputMu.Lock()
	defer q.outputMu.Unlock()
	return q.outputTruncated
}

func (q *runOutputEventQueue) Enqueue(stream, data string) {
	if q == nil || data == "" || q.coord == nil || q.runID == "" {
		return
	}
	if q.Disabled() {
		return
	}
	q.enqueue(q.eventInputs(stream, data))
}

func (q *runOutputEventQueue) eventInputs(stream, data string) []CoordinatorRunEventInput {
	q.outputMu.Lock()
	defer q.outputMu.Unlock()
	if q.outputTruncated {
		return nil
	}
	remaining := runEventOutputMaxBytes - q.outputBytes
	if remaining <= 0 {
		q.outputTruncated = true
		return []CoordinatorRunEventInput{outputTruncatedEventInput()}
	}
	truncated := false
	if len(data) > remaining {
		data = data[:remaining]
		truncated = true
	}
	q.outputBytes += len(data)
	if truncated {
		q.outputTruncated = true
	}
	events := []CoordinatorRunEventInput{{
		Type:   stream,
		Stream: stream,
		Data:   data,
	}}
	if truncated {
		events = append(events, outputTruncatedEventInput())
	}
	return events
}

func outputTruncatedEventInput() CoordinatorRunEventInput {
	return CoordinatorRunEventInput{
		Type:    "output.truncated",
		Phase:   "command",
		Message: fmt.Sprintf("stdout/stderr event capture capped at %d bytes; use crabbox logs for retained command output", runEventOutputMaxBytes),
	}
}

func (q *runOutputEventQueue) enqueue(events []CoordinatorRunEventInput) {
	if len(events) == 0 {
		return
	}
	q.queueOnce.Do(func() {
		q.events = make(chan CoordinatorRunEventInput, runEventOutputQueueSize)
		q.wg.Add(1)
		go q.post(q.events)
	})
	q.queueMu.Lock()
	defer q.queueMu.Unlock()
	if q.queueClosed || q.disabled {
		return
	}
	for _, event := range events {
		select {
		case q.events <- event:
		default:
			return
		}
	}
}

func (q *runOutputEventQueue) post(events <-chan CoordinatorRunEventInput) {
	defer q.wg.Done()
	for event := range events {
		ctx, cancel := context.WithTimeout(context.Background(), runEventOutputPostWait)
		_, err := q.coord.AppendRunEvent(ctx, q.runID, event)
		cancel()
		if err != nil && q.onError != nil && !q.onError(event.Type, err) {
			q.Disable()
			return
		}
	}
}

func (q *runOutputEventQueue) Disable() {
	if q == nil {
		return
	}
	q.queueMu.Lock()
	q.disabled = true
	q.queueMu.Unlock()
}

func (q *runOutputEventQueue) Disabled() bool {
	if q == nil {
		return true
	}
	q.queueMu.Lock()
	defer q.queueMu.Unlock()
	return q.disabled
}

func (q *runOutputEventQueue) CloseAndWait(timeout time.Duration) {
	if q == nil || q.events == nil {
		return
	}
	q.closeOnce.Do(func() {
		q.queueMu.Lock()
		defer q.queueMu.Unlock()
		q.queueClosed = true
		close(q.events)
	})
	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

type runEventStreamWriter struct {
	recorder *runRecorder
	stream   string
	data     strings.Builder
}

func (w *runEventStreamWriter) Write(p []byte) (int, error) {
	if w == nil || w.recorder == nil || w.recorder.runID == "" || w.recorder.finished || w.recorder.output == nil {
		return len(p), nil
	}
	written := len(p)
	for len(p) > 0 && !w.recorder.output.Closed() {
		space := runEventOutputChunkBytes - w.data.Len()
		if space <= 0 {
			w.Flush()
			continue
		}
		if space > len(p) {
			space = len(p)
		}
		_, _ = w.data.Write(p[:space])
		p = p[space:]
		if w.data.Len() >= runEventOutputChunkBytes {
			w.Flush()
		}
	}
	return written, nil
}

func (w *runEventStreamWriter) Flush() {
	if w == nil || w.recorder == nil || w.recorder.runID == "" || w.recorder.finished || w.recorder.output == nil || w.data.Len() == 0 {
		return
	}
	data := w.data.String()
	w.data.Reset()
	w.recorder.output.Enqueue(w.stream, data)
}
