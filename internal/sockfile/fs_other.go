//go:build !darwin && !freebsd && !netbsd && !openbsd && !linux

package sockfile

import "fmt"

// RequireLocalFS on a platform with no filesystem-type probe fails
// closed: a service socket whose backing filesystem cannot be
// classified is not a socket this package will vouch for.
func RequireLocalFS(path string) error {
	return fmt.Errorf("cannot determine filesystem type of %s on this platform — refusing to hold a service socket", path)
}
