//go:build unix

package execution

import (
	"os"
	"syscall"
)

// fileOwnerUID returns the uid owning info, when the platform reports
// file ownership.
func fileOwnerUID(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
