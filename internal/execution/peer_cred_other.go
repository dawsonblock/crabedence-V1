//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package execution

import (
	"fmt"
	"net"
)

// unixPeerCredentials fails closed on platforms without a supported
// peer credential mechanism: strict peer authentication cannot be
// weakened by running on an unrecognized platform.
func unixPeerCredentials(net.Conn) (PeerCredentials, error) {
	return PeerCredentials{}, fmt.Errorf("peer credentials unsupported on this platform")
}
