//go:build !unix

package qualprovider

import "os"

// privateDirOwner is a no-op where POSIX ownership does not apply; the
// mode check in ensurePrivateStateDir is all the platform supports. The
// loopback-only provider is not a supported qualification target there.
func privateDirOwner(dir string, info os.FileInfo) error {
	return nil
}
