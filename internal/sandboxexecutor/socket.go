package sandboxexecutor

import (
	"fmt"
	"os"
)

// ensureSocketDir creates (if needed) and verifies the socket
// directory: a real directory (not a symlink), owned by the current
// user, accessible only by its owner. An existing directory that is
// group/world accessible is tightened; if it cannot be tightened,
// startup fails. This is the OS-level boundary the executor's
// pathname identity checks rely on.
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
		return fmt.Errorf("socket path %s is occupied by a non-socket (mode %s); resolve it, do not delete it", path, info.Mode())
	}
	if err := verifyOwnership(path, info, "socket"); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// socketFileID identifies one filesystem object by device and inode.
// A path that later names a different object — the socket was deleted
// and a successor or attacker re-created the name — fails the identity
// comparison even though the name matches.
type socketFileID struct {
	dev uint64
	ino uint64
}

type socketIdentity = socketFileID

// socketIdentityFor verifies a freshly bound socket is a socket,
// owner-only, and owned by the current user — then returns its
// filesystem identity so cleanup can later remove only that same
// object.
func socketIdentityFor(path string) (*socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("socket path %s is not a socket after listen (mode %s)", path, info.Mode())
	}
	if err := verifyOwnership(path, info, "socket"); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("socket %s is group/world accessible (mode %04o)", path, perm)
	}
	return socketFileIdentity(info), nil
}

// removeOwnedSocket deletes the socket path the server bound, and only
// that object. A path that no longer names the bound socket — already
// removed, replaced by a successor, or swapped for a foreign file — is
// left alone rather than unlinked: the bytes at that name may belong
// to somebody else. An inspect failure, a foreign occupant, or a
// remove failure is an error; a path that already names nothing is a
// finished cleanup.
func removeOwnedSocket(path string, ident *socketIdentity) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot inspect socket path %s for cleanup: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path %s no longer names a socket (mode %s) — the occupant is not this server's to remove", path, info.Mode())
	}
	if current := socketFileIdentity(info); current != nil && ident != nil && *current != *ident {
		return fmt.Errorf("socket path %s names a socket this server did not bind — the occupant is not this server's to remove", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove socket %s: %w", path, err)
	}
	return nil
}

// socketFileIdentity is defined per-platform in owner_*.go.
