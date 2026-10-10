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

// socketFileIdentity returns the device+inode identity of the file
// described by info, or nil when the platform reports none. Two
// identities equal means the same filesystem object — a replaced path
// never matches the socket the service bound.
func socketFileIdentity(info os.FileInfo) *socketFileID {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return &socketFileID{dev: uint64(st.Dev), ino: st.Ino}
}
