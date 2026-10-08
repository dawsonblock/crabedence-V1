//go:build unix

package qualprovider

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// readFileNoFollow reads a regular file, refusing to follow a symlink at
// the final path component: an artifact path must name the bytes that
// were written, never whatever a link points at.
func readFileNoFollow(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file %s (%s)", path, info.Mode())
	}
	return io.ReadAll(f)
}
