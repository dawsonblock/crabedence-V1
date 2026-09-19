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
//
// With -envelope it prints the verifiable envelope instead: the digest
// plus the exact canonical descriptor bytes it covers, base64-encoded.
// A consumer (the standalone release verifier, NEMO, an operator)
// recomputes SHA-256 over the payload it was given — no Go toolchain and
// no second canonicalizer required.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

func main() {
	envelopeOnly := flag.Bool("envelope", false, "print the verifiable registry envelope (digest + canonical payload) instead of the bare digest")
	flag.Parse()

	registry := capability.NewRegistry()
	if err := execution.RegisterBuiltinCapabilities(registry); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
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
	if *envelopeOnly {
		payload, err := envelope.JSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "capability registry envelope failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(payload))
		return
	}
	fmt.Println(envelope.RegistrySHA256)
}
