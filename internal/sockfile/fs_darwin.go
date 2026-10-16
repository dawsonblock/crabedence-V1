//go:build darwin || freebsd || netbsd || openbsd

package sockfile

import (
	"fmt"
	"strings"
	"syscall"
)

// networkFSTypes names the filesystem families a custody or executor
// socket must never live on: storage whose occupant could be a remote
// host the kernel cannot arbitrate.
var networkFSTypes = map[string]bool{
	"nfs":    true,
	"smbfs":  true,
	"afpfs":  true,
	"webdav": true,
	"ftp":    true,
}

// RequireLocalFS verifies path sits on a kernel-local filesystem. A
// socket bound on network storage can be occupied or spoofed by a
// remote host outside this machine's ownership semantics — the
// path-identity and ownership checks above would attest a file whose
// bytes someone else controls. Inability to determine the filesystem
// type fails closed.
func RequireLocalFS(path string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fmt.Errorf("cannot determine filesystem type of %s: %w", path, err)
	}
	name := cName(st.Fstypename[:])
	if networkFSTypes[name] {
		return fmt.Errorf("socket directory %s is on %s — a network filesystem cannot hold a service socket", path, name)
	}
	return nil
}

func cName(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return strings.ToLower(string(out))
}
