//go:build unix

package sandboxexecutor

import (
	"os"
	"syscall"
)

// fileOwnerUID reports the kernel-recorded owner of a filesystem
// object. Unix platforms always supply it.
func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// socketFileIdentity returns the device+inode identity of the file
// described by info, or nil when the platform reports none. Two equal
// identities mean the same filesystem object — a replaced path never
// matches the socket this server bound.
func socketFileIdentity(info os.FileInfo) *socketFileID {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return &socketFileID{dev: uint64(stat.Dev), ino: stat.Ino}
}
