// Command registry-digest prints the authoritative capability
// registry's digest — the policy identity a release is qualified
// against.
//
// Release evidence embeds this value so an artifact binds the exact
// capability policy the runtime serves:
//
//	source commit → release → registry digest → runtime → effect receipt
//
// The digest is computed from the same built-in registry the execution
// service registers at startup, so the value in the evidence is the
// value the released service will serve.
package main

import (
	"fmt"
	"os"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

func main() {
	registry := capability.NewRegistry()
	for name, register := range map[string]func(*capability.Registry) error{
		"system.echo":            execution.RegisterEchoCapability,
		"test.counter.increment": execution.RegisterCounterCapability,
		"system.info":            execution.RegisterSystemInfoCapability,
		"github.issue.create":    execution.RegisterGitHubIssueCapability,
		"github.issue.get":       execution.RegisterGitHubReadCapabilities,
	} {
		if err := register(registry); err != nil {
			fmt.Fprintf(os.Stderr, "register %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	if err := registry.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "capability registry invariant scan failed: %v\n", err)
		os.Exit(1)
	}
	envelope, err := registry.Envelope()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capability registry digest failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(envelope.RegistrySHA256)
}
