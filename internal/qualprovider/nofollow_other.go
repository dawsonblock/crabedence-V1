//go:build !unix

package qualprovider

import (
	"fmt"
	"io"
	"os"
)

// readFileNoFollow reads a regular file without following a symlink. On
// platforms without O_NOFOLLOW the link check is a pre-open lstat, which
// is racy by nature; the platform is not a supported qualification
// target for the loopback-only provider.
func readFileNoFollow(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlink %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file %s (%s)", path, st.Mode())
	}
	return io.ReadAll(f)
}
