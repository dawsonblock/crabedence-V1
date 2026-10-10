package execution

// PeerCredentials is everything the kernel will tell us about the
// process on the other end of a Unix connection — the caller's
// evidence, not its claim.
//
// UID is available on every supported platform. PID and ExePath are
// best-effort platform evidence: Linux reports the peer PID via
// SO_PEERCRED and the executable via /proc/<pid>/exe; the BSDs supply
// only the credential UID. A zero PID or empty ExePath means the
// platform cannot supply it — never that the peer has none.
type PeerCredentials struct {
	UID     uint32
	PID     int32
	ExePath string
}

// PeerEvidence is the kernel-supplied local-caller identity carried
// on the request for durable provenance — server-resolved, never
// trusted from the wire. UID is present whenever credential
// resolution succeeded; PID and Executable are populated where the
// kernel reports them (Linux). Nil/empty means the platform cannot
// supply the field — never that the peer has none.
type PeerEvidence struct {
	UID        *int64
	PID        *int64
	Executable string
}

// Evidence converts the resolved credentials to the provenance form
// carried on the request and persisted on the record. UID is always
// present — a PeerCredentials only exists when the kernel reported
// one — so it is the pointer that distinguishes "root invoked" (0)
// from "platform cannot say" (nil).
func (c PeerCredentials) Evidence() *PeerEvidence {
	uid := int64(c.UID)
	ev := &PeerEvidence{UID: &uid, Executable: c.ExePath}
	if c.PID != 0 {
		pid := int64(c.PID)
		ev.PID = &pid
	}
	return ev
}
