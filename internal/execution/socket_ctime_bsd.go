//go:build darwin || ios || freebsd || dragonfly || netbsd || openbsd

package execution

import "syscall"

// socketCTimeOf returns the inode change time in nanoseconds.
func socketCTimeOf(st *syscall.Stat_t) int64 {
	return st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec
}
