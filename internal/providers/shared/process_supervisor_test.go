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
		Name: "test-vm-1",
		Keep: false,
	})
	if err != nil {
		t.Fatalf("start 1: %v", err)
	}
	if h1.PID() <= 0 {
		t.Fatalf("pid = %d, want positive", h1.PID())
	}

	h2, err := sup.Start(context.Background(), ProcessStartRequest{
		Name: "test-vm-2",
		Keep: true,
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

	// Handoff is a capability interface — type-assert to use it.
	handoff, ok := h.(ProcessHandoff)
	if !ok {
		t.Fatal("handle does not implement ProcessHandoff")
	}
	if err := handoff.Handoff(); err != nil {
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

	// Done is a capability interface — type-assert to use it.
	obs, ok := h.(ExitObservable)
	if !ok {
		t.Fatal("handle does not implement ExitObservable")
	}
	select {
	case <-obs.Done():
	default:
		t.Fatal("Done not closed after abort")
	}
}

func TestFakeProcessSupervisorStartFailure(t *testing.T) {
	sup := &FakeProcessSupervisor{}
	// nextStartOK defaults to false, so the first start fails.
	_, err := sup.Start(context.Background(), ProcessStartRequest{Name: "first"})
	if err == nil {
		t.Fatal("expected failure when nextStartOK is false")
	}
	// After SetNextStartOK(true), the next start succeeds.
	sup.SetNextStartOK(true)
	_, err = sup.Start(context.Background(), ProcessStartRequest{Name: "second"})
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
}

func TestFakeProcessHandleAbortIsIdempotent(t *testing.T) {
	sup := &FakeProcessSupervisor{}
	sup.SetNextStartOK(true)
	h, err := sup.Start(context.Background(), ProcessStartRequest{Name: "test"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	fh := sup.Handles()[0].(*fakeProcessHandle)
	cause := errors.New("readiness failed")
	if err := h.Abort(cause); err != cause {
		t.Fatalf("first abort: got %v, want %v", err, cause)
	}
	// Second abort should not panic and should return the new error.
	cause2 := errors.New("second abort")
	if err := h.Abort(cause2); err != cause2 {
		t.Fatalf("second abort: got %v, want %v", err, cause2)
	}
	if !fh.Aborted() {
		t.Fatal("abort not recorded")
	}
	obs, ok := h.(ExitObservable)
	if !ok {
		t.Fatal("handle does not implement ExitObservable")
	}
	select {
	case <-obs.Done():
	default:
		t.Fatal("Done not closed after abort")
	}
}
