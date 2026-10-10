//go:build !unix

package execution

import (
	"os"
	"sync"
)

// The service's checkpoint stream is a unix-socket deployment concern;
// on non-unix platforms the writer lock degrades to a process-local
// mutex so single-process concurrent emitters still serialize. It
// cannot protect against a second process on the same path — the
// platform has no flock primitive wired here.
var checkpointWriterLocks sync.Map // path -> *sync.Mutex

func lockCheckpointWriter(lockPath string) (func() error, error) {
	fh, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	mu, _ := checkpointWriterLocks.LoadOrStore(lockPath, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return func() error {
		mu.(*sync.Mutex).Unlock()
		return fh.Close()
	}, nil
}
