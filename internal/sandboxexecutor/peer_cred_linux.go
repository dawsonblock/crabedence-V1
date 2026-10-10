//go:build linux

package sandboxexecutor

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// unixPeerCredentials returns the kernel-supplied credential of the
// process on the other end of a Unix stream connection via SO_PEERCRED.
func unixPeerCredentials(conn net.Conn) (PeerCredentials, error) {
	raw, ok := conn.(syscall.Conn)
	if !ok {
		return PeerCredentials{}, fmt.Errorf("connection does not expose peer credentials")
	}
	var credentials *unix.Ucred
	var controlErr error
	rawConn, err := raw.SyscallConn()
	if err != nil {
		return PeerCredentials{}, fmt.Errorf("inspect Unix peer: %w", err)
	}
	if err := rawConn.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return PeerCredentials{}, fmt.Errorf("inspect Unix peer: %w", err)
	}
	if controlErr != nil {
		return PeerCredentials{}, fmt.Errorf("inspect Unix peer: %w", controlErr)
	}
	if credentials == nil {
		return PeerCredentials{}, fmt.Errorf("peer credentials unavailable")
	}
	return PeerCredentials{UID: credentials.Uid}, nil
}
