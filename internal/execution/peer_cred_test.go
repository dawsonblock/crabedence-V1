package execution

import (
	"net"
	"os"
	"runtime"
	"testing"
)

// unixConnPair returns a connected server-side Unix conn — the side
// whose peer credentials the kernel reports.
func unixConnPair(t *testing.T) net.Conn {
	t.Helper()
	l, err := net.Listen("unix", testSocketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	srv := <-accepted
	t.Cleanup(func() { srv.Close() })
	return srv
}

func TestUnixPeerCredentialsResolvePeer(t *testing.T) {
	creds, err := unixPeerCredentials(unixConnPair(t))
	if err != nil {
		t.Fatalf("peer credentials: %v", err)
	}
	// The dialer is this process — the kernel must report our own UID.
	if want := uint32(os.Getuid()); creds.UID != want {
		t.Fatalf("peer uid = %d, want %d", creds.UID, want)
	}
	switch runtime.GOOS {
	case "linux":
		// Linux SO_PEERCRED carries the peer PID and /proc resolves
		// the executable: the full local-caller binding.
		if creds.PID != int32(os.Getpid()) {
			t.Fatalf("peer pid = %d, want %d", creds.PID, os.Getpid())
		}
		if creds.ExePath == "" {
			t.Fatal("linux must resolve the peer executable")
		}
		if _, err := os.Stat(creds.ExePath); err != nil {
			t.Fatalf("reported executable %q is not a real path: %v", creds.ExePath, err)
		}
	default:
		// The BSD credential carries the UID only — PID/exe stay
		// empty rather than carrying fabricated evidence.
		if creds.PID != 0 || creds.ExePath != "" {
			t.Fatalf("non-linux kernel must not fabricate pid/exe evidence: %+v", creds)
		}
	}
}

func TestUnixPeerCredentialsRejectsNonUnix(t *testing.T) {
	// A conn that does not expose syscall.Conn cannot yield kernel
	// evidence — resolution fails rather than guessing.
	if _, err := unixPeerCredentials(nil); err == nil {
		t.Fatal("nil conn must fail closed")
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, err := unixPeerCredentials(server); err == nil {
		t.Fatal("a non-kernel conn must fail closed")
	}
}

func TestPeerCredentialsEvidence(t *testing.T) {
	// UID 0 (root) is evidence, not absence: the pointer, not the
	// value, carries "the platform could not say".
	ev := PeerCredentials{UID: 0}.Evidence()
	if ev.UID == nil || *ev.UID != 0 {
		t.Fatal("uid 0 must round-trip as a present 0, not nil")
	}
	if ev.PID != nil || ev.Executable != "" {
		t.Fatal("unsupplied fields must stay absent, not zero-fabricated")
	}
	ev = PeerCredentials{UID: 501, PID: 42, ExePath: "/usr/local/bin/nemo-relay"}.Evidence()
	if ev.UID == nil || *ev.UID != 501 || ev.PID == nil || *ev.PID != 42 ||
		ev.Executable != "/usr/local/bin/nemo-relay" {
		t.Fatalf("full evidence must carry every reported field: %+v", ev)
	}
}
