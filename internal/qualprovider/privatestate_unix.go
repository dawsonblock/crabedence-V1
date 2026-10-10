//go:build unix

package qualprovider

import (
	"fmt"
	"os"
	"syscall"
)

// privateDirOwner refuses a state directory not owned by the process's
// effective uid: acknowledged truth must not live in storage another
// principal controls.
func privateDirOwner(dir string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("state directory %s: cannot determine ownership", dir)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("state directory %s is owned by uid %d, not the provider uid %d", dir, st.Uid, os.Geteuid())
	}
	return nil
}
