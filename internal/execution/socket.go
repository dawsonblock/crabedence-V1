package execution

import (
	"fmt"
	"os"
)

// Socket-path hardening. The execution service is a trust boundary:
// any local user who can reach the socket can submit capability
// invocations, so startup fails closed when directory or socket
// permissions cannot be guaranteed. Nothing at the configured path is
// ever removed unless it is provably a stale socket owned by the
// current user.

// ensureSocketDir creates (if needed) and verifies the socket
// directory: a real directory (not a symlink), owned by the current
// user, accessible only by its owner. An existing directory that is
// group/world accessible is tightened; if it cannot be tightened,
// startup fails.
func ensureSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect socket directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket directory %s is a symlink; refusing to use it", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("socket directory %s is not a directory", dir)
	}
	if err := verifyOwnership(dir, info, "socket directory"); err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure socket directory permissions on %s: %w", dir, err)
	}
	info, err = os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("re-inspect socket directory %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("socket directory %s is group/world accessible (mode %04o) and could not be secured", dir, perm)
	}
	return nil
}

// clearStaleSocket removes an existing socket at path so a new
// listener can bind. It refuses to remove anything that is not a Unix
// socket owned by the current user: a regular file, directory, or
// symlink occupying the configured path is an operator error (or an
// attack), never something to delete silently.
func clearStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect socket path %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket path %s is a symlink; refusing to remove it", path)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path %s exists and is not a socket (mode %s); refusing to remove it", path, info.Mode())
	}
	if err := verifyOwnership(path, info, "socket"); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// verifySocketFile confirms a freshly bound socket is owner-only and
// owned by the current user — the chmod result is verified, not
// assumed.
func verifySocketFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path %s is not a socket after listen (mode %s)", path, info.Mode())
	}
	if err := verifyOwnership(path, info, "socket"); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("socket %s is group/world accessible (mode %04o)", path, perm)
	}
	return nil
}

// verifyOwnership checks that info describes a path owned by the
// current user. Platforms without Unix file ownership report no
// ownership information and skip the check.
func verifyOwnership(path string, info os.FileInfo, kind string) error {
	uid, ok := fileOwnerUID(info)
	if !ok {
		return nil
	}
	if current := os.Getuid(); current >= 0 && uid != current {
		return fmt.Errorf("%s %s is owned by uid %d, not the current user (uid %d)", kind, path, uid, current)
	}
	return nil
}
