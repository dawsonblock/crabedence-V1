//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package execution

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// unixPeerUID returns the UID of the process on the other end of a
// Unix stream connection via LOCAL_PEERCRED (Xucred). The kernel
// supplies the credential — it cannot be forged by the caller.
func unixPeerUID(conn net.Conn) (uint32, error) {
	raw, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("connection does not expose peer credentials")
	}
	var credentials *unix.Xucred
	var controlErr error
	rawConn, err := raw.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("inspect Unix peer: %w", err)
	}
	if err := rawConn.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("inspect Unix peer: %w", err)
	}
	if controlErr != nil {
		return 0, fmt.Errorf("inspect Unix peer: %w", controlErr)
	}
	if credentials == nil {
		return 0, fmt.Errorf("peer credentials unavailable")
	}
	return credentials.Uid, nil
}
