//go:build linux

package execution

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// unixPeerCredentials returns the kernel-supplied credentials of the
// process on the other end of a Unix stream connection via SO_PEERCRED
// (UID and PID) plus the peer's executable resolved through
// /proc/<pid>/exe. None of it can be forged by the caller: the UID/PID
// are the kernel's record, and the executable is whichever binary the
// peer actually is — a same-UID process that execs another binary then
// IS that binary.
//
// The executable is evidence, not a policy input: a vanished peer
// (readlink failure) yields an empty path rather than a failed call.
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
	creds := PeerCredentials{UID: credentials.Uid, PID: credentials.Pid}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", credentials.Pid)); err == nil {
		creds.ExePath = exe
	}
	return creds, nil
}
