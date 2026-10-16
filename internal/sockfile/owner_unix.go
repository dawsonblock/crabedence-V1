//go:build unix

package sockfile

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

// fileIdentity returns the device+inode identity of the file
// described by info, or nil when the platform reports none. Two equal
// identities mean the same filesystem object — a replaced path never
// matches the socket this server bound.
func fileIdentity(info os.FileInfo) *FileID {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return &FileID{dev: uint64(stat.Dev), ino: stat.Ino}
}
