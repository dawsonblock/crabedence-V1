package idempotency

import "os"

// osGetpid returns the current process ID.
// Wrapped for testability.
var osGetpid = os.Getpid
