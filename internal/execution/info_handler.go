package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// SystemInfoHandler implements the system.info capability.
// This is a READ capability — it goes through the remote execution port
// (not local like PURE), proving NEMO → Go service end-to-end.
// It returns system information: Go version, OS, arch, timestamp.
type SystemInfoHandler struct{}

// NewSystemInfoHandler creates a handler for system.info.
func NewSystemInfoHandler() *SystemInfoHandler {
	return &SystemInfoHandler{}
}

// Execute returns system information.
func (h *SystemInfoHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	runID := fmt.Sprintf("sysinfo-%d", time.Now().UnixNano())

	result, _ := json.Marshal(map[string]any{
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"principal":  req.Authority.Principal,
		"capability": req.Capability,
	})

	return Response{
		Status: StatusSucceeded,
		Result: result,
		Execution: &ExecutionMeta{
			Provider: "system-info",
			RunID:    runID,
		},
	}
}

// RegisterSystemInfoCapability registers system.info as a READ capability.
// READ capabilities go through the remote execution port, proving
// NEMO → Go service connectivity end-to-end.
func RegisterSystemInfoCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "system.info",
		ExecutionClass: capability.ClassRead,
		AdapterID:      "system-info",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "system.info",
			GrantRequired: false,
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
	})
}
