//go:build unix

package sandboxexecutor

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The kernel, not the caller, supplies the UID the allowlist checks.
func TestUnixPeerCredentials(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type result struct {
		creds PeerCredentials
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer conn.Close()
		creds, err := unixPeerCredentials(conn)
		resCh <- result{creds, err}
	}()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("peer credentials: %v", res.err)
	}
	if res.creds.UID != uint32(os.Getuid()) {
		t.Fatalf("kernel reported uid %d for our own connection (uid %d)", res.creds.UID, os.Getuid())
	}
}
