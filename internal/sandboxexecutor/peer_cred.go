package sandboxexecutor

// PeerCredentials is what the kernel reports about the process on the
// other end of a Unix connection — the caller's evidence, not its
// claim. The sandbox executor authenticates local submitters by their
// kernel-supplied UID; anything a caller says about itself is input,
// not identity.
type PeerCredentials struct {
	UID uint32
}
