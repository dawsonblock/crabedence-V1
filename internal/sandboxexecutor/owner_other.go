//go:build !unix

package sandboxexecutor

import "os"

// fileOwnerUID reports that this platform cannot supply a
// kernel-verified owner. Callers must fail closed.
func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	return 0, false
}

// socketFileIdentity reports no identity on platforms without inode
// semantics. Callers treat nil as "cannot compare" and skip the
// identity check rather than assuming a match.
func socketFileIdentity(info os.FileInfo) *socketFileID {
	return nil
}
