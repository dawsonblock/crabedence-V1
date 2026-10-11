// Command sandbox-job-sign is the authority-side counterpart of
// sandbox-executord: it signs a SandboxJobV2 contract with an
// Ed25519 key and emits the wire envelope the executor accepts.
// Signing keys, approval logic, and privileged credentials live
// here — outside the executor's process and outside every guest VM.
//
// Usage:
//
//	sandbox-job-sign -key-file authority.pem -contract job.json > envelope.json
//	sandbox-job-sign -key-file authority.pem -generate   # create a key
//
// The generated authority public key fingerprint is printed to
// stderr; that fingerprint line (or the bare base64 key printed by
// -print-pubkey) goes into the executor's -job-pubkey-file trust
// list. The contract file must already carry every field — including
// job_id, nonce, issued_at/expires_at, and the authority fingerprint,
// which -generate prints once. The tool refuses to sign a contract
// whose authority field does not match the key.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

func main() {
	keyFile := flag.String("key-file", "", "PKCS8 PEM Ed25519 private key")
	contractFile := flag.String("contract", "", "SandboxJobV2 contract JSON to sign")
	generate := flag.Bool("generate", false, "generate a new key at -key-file (refuses to clobber)")
	printPubkey := flag.Bool("print-pubkey", false, "print the base64 public key and fingerprint, then exit")
	flag.Parse()

	if *keyFile == "" {
		fmt.Fprintln(os.Stderr, "sandbox-job-sign: -key-file is required")
		os.Exit(2)
	}

	if *generate {
		key, err := generateKey(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sandbox-job-sign: %v\n", err)
			os.Exit(1)
		}
		reportIdentity(key)
		return
	}

	key, err := loadKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-job-sign: %v\n", err)
		os.Exit(1)
	}
	if *printPubkey {
		reportIdentity(key)
		return
	}
	if *contractFile == "" {
		fmt.Fprintln(os.Stderr, "sandbox-job-sign: -contract is required (or -generate / -print-pubkey)")
		os.Exit(2)
	}
	data, err := os.ReadFile(*contractFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-job-sign: read contract: %v\n", err)
		os.Exit(1)
	}
	contract, err := sandboxexecutor.ParseContract(json.RawMessage(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-job-sign: %v\n", err)
		os.Exit(1)
	}
	env, err := sandboxexecutor.SignContract(key, contract)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-job-sign: %v\n", err)
		os.Exit(1)
	}
	out, err := json.Marshal(map[string]any{"signed_job": env})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-job-sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func reportIdentity(key ed25519.PrivateKey) {
	pub := key.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr, "authority fingerprint: %s\n", sandboxexecutor.AuthorityFingerprint(pub))
	fmt.Fprintf(os.Stderr, "public key (base64):   %s\n", base64.StdEncoding.EncodeToString(pub))
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect key %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("key %s is a symlink", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("key %s is group/world accessible (mode %04o) — tighten it before use", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	return parsePKCS8(data)
}

func parsePKCS8(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key is not PEM encoded")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("key is not a PKCS8 private key")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("key file has trailing data")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ed25519 key")
	}
	return key, nil
}

// generateKey creates a key with the same crash-durable publish
// discipline as the evidence signer: temp file, fsync, atomic
// no-clobber link, directory fsync.
func generateKey(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".jobkey-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("key %s already exists — refusing to clobber it", path)
		}
		return nil, err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return key, nil
}
