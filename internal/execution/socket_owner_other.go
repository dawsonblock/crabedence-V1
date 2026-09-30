//go:build !unix

package execution

import "os"

// fileOwnerUID reports no ownership information on platforms without
// Unix file ownership (Windows). The execution service is not
// functional there, but the package must still build.
func fileOwnerUID(info os.FileInfo) (int, bool) {
	return 0, false
}
