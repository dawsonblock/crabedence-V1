//go:build unix

package execution

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockCheckpointWriter takes the advisory exclusive lock that
// serializes checkpoint writers on one host. Two services pointed at
// the same checkpoint path — or a restarted service overlapping its
// predecessor — must never interleave sequence allocation and appends:
// the flock makes the verify-then-append critical section atomic
// across processes. The returned release drops the lock and closes the
// lock file.
func lockCheckpointWriter(lockPath string) (func() error, error) {
	fh, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(fh.Fd()), unix.LOCK_EX); err != nil {
		fh.Close()
		return nil, err
	}
	return func() error {
		return errors.Join(unix.Flock(int(fh.Fd()), unix.LOCK_UN), fh.Close())
	}, nil
}
