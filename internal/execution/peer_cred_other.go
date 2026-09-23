//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package execution

import (
	"fmt"
	"net"
)

// unixPeerUID fails closed on platforms without a supported peer
// credential mechanism: strict peer authentication cannot be weakened
// by running on an unrecognized platform.
func unixPeerUID(net.Conn) (uint32, error) {
	return 0, fmt.Errorf("peer credentials unsupported on this platform")
}
