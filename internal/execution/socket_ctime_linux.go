//go:build linux || android

package execution

import "syscall"

// socketCTimeOf returns the inode change time in nanoseconds.
func socketCTimeOf(st *syscall.Stat_t) int64 {
	return st.Ctim.Sec*1e9 + st.Ctim.Nsec
}
