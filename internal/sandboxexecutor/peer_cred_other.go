//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package sandboxexecutor

import (
	"fmt"
	"net"
)

// unixPeerCredentials reports that this platform cannot supply a
// kernel-verified peer identity. The executor refuses to run without
// one: a submission channel that cannot prove who called is not a
// submission channel.
func unixPeerCredentials(conn net.Conn) (PeerCredentials, error) {
	return PeerCredentials{}, fmt.Errorf("peer credentials unsupported on this platform")
}
