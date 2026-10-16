// Package sockfile is the shared Unix-socket file discipline for the
// executor and custody daemons: the directory a service socket is
// bound inside, what may occupy the socket path, and which object a
// server may unlink when it stops.
//
// The guarantees it enforces:
//
//   - a socket directory is a real, owner-only directory on a local
//     filesystem — never a symlink, never another user's directory,
//     never network storage a remote host could occupy behind the
//     kernel's back;
//   - an existing occupant at the socket path is cleared only when it
//     is provably stale: a socket, owned by this process's user, and
//     not answering live connections. A live listener — another
//     running service — is refused, never unlinked;
//   - a server unlinks only the exact filesystem object it bound
//     (device+inode identity). A path swapped for a successor socket
//     or a foreign file is left alone.
package sockfile

import (
	"fmt"
	"net"
	"os"
	"time"
)

// EnsureDir creates (if needed) and verifies a socket directory: a
// real directory (not a symlink), owned by the current user, on a
// local filesystem, accessible only by its owner. An existing
// directory that is group/world accessible is tightened; if it cannot
// be tightened, startup fails. This is the OS-level boundary the
// daemons' pathname identity checks rely on.
func EnsureDir(dir string) error {
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
	if err := VerifyOwnership(dir, info, "socket directory"); err != nil {
		return err
	}
	if err := RequireLocalFS(dir); err != nil {
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

// ProbeAlive reports whether a live listener answers at the socket
// path — the difference between a stale socket a crashed service left
// behind and a running service's socket. A probe that cannot be
// answered means the occupant is stale.
func ProbeAlive(path string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("unix", path)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ClearStale removes an existing socket at path so a new listener can
// bind. It refuses to remove anything that is not a verifiably stale
// Unix socket owned by the current user: a regular file, directory, or
// symlink occupying the configured path is an operator error (or an
// attack), never something to delete silently — and a socket another
// live service still answers on is that service's, not this one's to
// take. probeAlive detects the live occupant; a nil probe treats any
// owned socket as clearable (the caller takes the responsibility).
func ClearStale(path string, probeAlive func(string) bool) error {
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
	if err := VerifyOwnership(path, info, "socket"); err != nil {
		return err
	}
	if probeAlive != nil && probeAlive(path) {
		return fmt.Errorf("socket path %s answers a live connection — a running service owns it; refusing to remove another daemon's socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// FileID identifies one filesystem object by device and inode. A path
// that later names a different object — the socket was deleted and a
// successor or attacker re-created the name — fails the identity
// comparison even though the name matches.
type FileID struct {
	dev uint64
	ino uint64
}

// SocketIdentity is the bound-socket identity a server keeps for its
// lifetime so cleanup removes only that object.
type SocketIdentity = FileID

// IdentityFor verifies a freshly bound socket is a socket, owner-only,
// and owned by the current user — then returns its filesystem identity
// so cleanup can later remove only that same object.
func IdentityFor(path string) (*SocketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("socket path %s is not a socket after listen (mode %s)", path, info.Mode())
	}
	if err := VerifyOwnership(path, info, "socket"); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("socket %s is group/world accessible (mode %04o)", path, perm)
	}
	return fileIdentity(info), nil
}

// RemoveOwned deletes the socket path the server bound, and only that
// object. A path that no longer names the bound socket — already
// removed, replaced by a successor, or swapped for a foreign file — is
// left alone rather than unlinked: the bytes at that name may belong
// to somebody else. An inspect failure, a foreign occupant, or a
// remove failure is an error; a path that already names nothing is a
// finished cleanup.
func RemoveOwned(path string, ident *SocketIdentity) error {
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
	if current := fileIdentity(info); current != nil && ident != nil && *current != *ident {
		return fmt.Errorf("socket path %s names a socket this server did not bind — the occupant is not this server's to remove", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove socket %s: %w", path, err)
	}
	return nil
}

// VerifyOwnership checks the file is owned by the current user. Shared
// by the socket-path checks and the credential loaders — a file
// another user can replace is not a credential. Inability to
// determine the owner fails closed.
func VerifyOwnership(path string, info os.FileInfo, what string) error {
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("%s %s: cannot determine owner", what, path)
	}
	if uid != uint32(os.Getuid()) {
		return fmt.Errorf("%s %s is owned by uid %d, not the process uid %d", what, path, uid, os.Getuid())
	}
	return nil
}

// FsyncDir commits a directory's metadata so a rename or unlink made
// inside it survives a power loss. A durability boundary that skips
// this may keep the file's bytes durable while losing the name —
// which for a custody store is the same as losing the file.
func FsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory %s for durability commit: %w", dir, err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return fmt.Errorf("directory fsync %s: %w", dir, serr)
	}
	if cerr != nil {
		return fmt.Errorf("directory close %s after fsync: %w", dir, cerr)
	}
	return nil
}
