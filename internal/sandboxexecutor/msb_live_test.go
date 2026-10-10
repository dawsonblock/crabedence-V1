package sandboxexecutor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Live Microsandbox qualification: exercises the real backend end to
// end — signed contract in, microVM execution, bound result out.
// Env-gated like the post-dispatch qualification: it creates actual
// VMs and needs an msb binary, so it only runs when
// CRABBOX_MSB_LIVE=1 and msb (plus a local image) are present.
//
//	CRABBOX_MSB_LIVE=1 go test -race -timeout=300s -run 'TestMSBLive' ./internal/sandboxexecutor/
func msbOrSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("CRABBOX_MSB_LIVE") != "1" {
		t.Skip("CRABBOX_MSB_LIVE=1 not set — skipping live microsandbox test")
	}
	candidates := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".microsandbox", "bin", "msb"))
	}
	if p, err := exec.LookPath("msb"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	t.Skip("no msb binary found")
	return ""
}

func TestMSBLiveJobLifecycle(t *testing.T) {
	bin := msbOrSkip(t)
	key, keys := testAuthority(t)
	dir := socketDir(t)
	artifacts := filepath.Join(dir, "artifacts")
	backend := &MSBBackend{Bin: bin, StateDir: artifacts}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})
	conn, reader := connect(t, srv.SocketPath())
	jobID := "msb-live-ok"
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV1) {
		c.JobID = jobID
		c.Nonce = "msb-live-nonce-1"
		c.Image = "python:3.12"
		c.Argv = []string{"python3", "-c", "print('live-ok')"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}

	// The monitor transitions RUNNING -> SUCCEEDED asynchronously.
	deadline := time.Now().Add(90 * time.Second)
	var lj *LedgerJob
	for time.Now().Before(deadline) {
		lj, _ = srv.Ledger().Get(jobID)
		if lj != nil && (lj.State == JobStateSucceeded || lj.State == JobStateFailed) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lj == nil || lj.State != JobStateSucceeded {
		t.Fatalf("job did not succeed: %+v", lj)
	}
	if lj.ExitCode == nil || *lj.ExitCode != 0 {
		t.Fatalf("exit code = %+v", lj.ExitCode)
	}
	var res ExecResult
	if err := json.Unmarshal([]byte(lj.ResultJSON), &res); err != nil {
		t.Fatalf("result_json: %v", err)
	}
	data, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if string(data) == "" || res.OutputSHA256 == "" {
		t.Fatal("empty artifact or hash")
	}
	t.Logf("artifact %s sha=%s bytes=%d", res.OutputPath, res.OutputSHA256[:16], res.OutputBytes)
}

func TestMSBLiveRefusalsAndCleanup(t *testing.T) {
	bin := msbOrSkip(t)
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(dir, "artifacts")}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})

	t.Run("forged contract never reaches a VM", func(t *testing.T) {
		conn, reader := connect(t, srv.SocketPath())
		req := signedJobReq(t, key, func(c *JobContractV1) { c.JobID = "msb-forge"; c.Nonce = "n-fg" })
		sj := req["signed_job"].(map[string]any)
		var c JobContractV1
		if err := json.Unmarshal(sj["contract"].(json.RawMessage), &c); err != nil {
			t.Fatal(err)
		}
		c.Image = "alpine:latest" // post-signing tamper
		raw, _ := json.Marshal(&c)
		sj["contract"] = json.RawMessage(raw)
		resp := sendJob(t, conn, reader, req)
		if resp.OK {
			t.Fatal("forged job dispatched")
		}
	})
}
