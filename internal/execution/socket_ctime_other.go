//go:build unix && !linux && !android && !darwin && !ios && !freebsd && !dragonfly && !netbsd && !openbsd

package execution

import "syscall"

// socketCTimeOf reports no change time on platforms where Stat_t does
// not expose one under a known field name; identity there degrades to
// device+inode, the same discrimination the check always had.
func socketCTimeOf(st *syscall.Stat_t) int64 {
	return 0
}
