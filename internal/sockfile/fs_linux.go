//go:build linux

package sockfile

import (
	"fmt"
	"syscall"
)

// networkFSMagics are the f_type magic numbers of filesystems a
// custody or executor socket must never live on — storage whose
// occupant could be a remote host the kernel cannot arbitrate.
var networkFSMagics = map[int64]string{
	0x6969:     "nfs",
	0x517b:     "smb",
	0xff534d42: "cifs",
	0x00c36400: "ceph",
	0x5346414f: "afs",
	0x01021997: "9p",
	0x6e667364: "nfsd",
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
	if name, bad := networkFSMagics[st.Type]; bad {
		return fmt.Errorf("socket directory %s is on %s — a network filesystem cannot hold a service socket", path, name)
	}
	return nil
}
