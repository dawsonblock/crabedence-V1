package shared

import (
	"context"
	"errors"
	"testing"
)

func TestFakeProcessSupervisorRecordsStarts(t *testing.T) {
	sup := &FakeProcessSupervisor{}
	sup.SetNextStartOK(true)

	h1, err := sup.Start(context.Background(), ProcessStartRequest{
		Name:    "test-vm-1",
		Keep:    false,
		Command: []string{"tart", "run", "test-vm-1"},
	})
	if err != nil {
		t.Fatalf("start 1: %v", err)
	}
	if h1.PID() <= 0 {
		t.Fatalf("pid = %d, want positive", h1.PID())
	}

	h2, err := sup.Start(context.Background(), ProcessStartRequest{
		Name:    "test-vm-2",
		Keep:    true,
		Command: []string{"lume", "run", "test-vm-2"},
	})
	if err != nil {
		t.Fatalf("start 2: %v", err)
	}
	if h2.PID() == h1.PID() {
		t.Fatal("pids must differ")
	}

	starts := sup.Starts()
	if len(starts) != 2 {
		t.Fatalf("starts = %d, want 2", len(starts))
	}
	if starts[0].Request.Name != "test-vm-1" || !starts[1].Request.Keep {
		t.Fatalf("recorded starts = %+v", starts)
	}
}

func TestFakeProcessHandleAbortAndHandoff(t *testing.T) {
	sup := &FakeProcessSupervisor{}
	sup.SetNextStartOK(true)

	h, err := sup.Start(context.Background(), ProcessStartRequest{Name: "test-vm"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	fh := sup.Handles()[0].(*fakeProcessHandle)

	if err := h.Handoff(); err != nil {
		t.Fatalf("handoff: %v", err)
	}
	if !fh.HandedOff() {
		t.Fatal("handoff not recorded")
	}

	cause := errors.New("readiness failed")
	if err := h.Abort(cause); err == nil {
		t.Fatal("expected joined error from abort")
	}
	if !fh.Aborted() {
		t.Fatal("abort not recorded")
	}

	select {
	case <-h.Done():
	default:
		t.Fatal("Done not closed after abort")
	}
}

func TestFakeProcessSupervisorStartFailure(t *testing.T) {
	sup := &FakeProcessSupervisor{}
	// First start succeeds (nextStartOK defaults to false, but first call
	// always succeeds to allow initial setup).
	_, err := sup.Start(context.Background(), ProcessStartRequest{Name: "first"})
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	// Second start fails because nextStartOK is false.
	_, err = sup.Start(context.Background(), ProcessStartRequest{Name: "second"})
	if err == nil {
		t.Fatal("expected failure on second start")
	}
}
