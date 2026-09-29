package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRunDownloadSpec(t *testing.T) {
	got, err := parseRunDownloadSpec(`out/sixel.bin=/tmp/sixel.bin`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Remote != "out/sixel.bin" || got.Local != "/tmp/sixel.bin" {
		t.Fatalf("spec=%#v", got)
	}
	if _, err := parseRunDownloadSpec("out.bin"); err == nil {
		t.Fatal("expected missing local path to fail")
	}
}

func TestPreflightRunLocalOutputsRejectsBadInputs(t *testing.T) {
	if err := preflightRunLocalOutputs("", "", []string{"out.bin"}); err == nil {
		t.Fatal("expected malformed download to fail")
	}
	if err := preflightRunLocalOutputs(t.TempDir()+"/missing/stdout.bin", "", nil); err == nil {
		t.Fatal("expected missing capture directory to fail")
	}
	if err := preflightRunLocalOutputs("", "", []string{"remote.out=" + t.TempDir()}); err == nil {
		t.Fatal("expected download to existing directory to fail")
	}
	fileParent := t.TempDir() + "/not-a-dir"
	if err := os.WriteFile(fileParent, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := preflightRunLocalOutputs("", "", []string{"remote.out=" + fileParent + "/out.bin"}); err == nil {
		t.Fatal("expected download parent file to fail")
	}
}

func TestPreflightRunLocalOutputsValidatesCaptureFile(t *testing.T) {
	path := t.TempDir() + "/stdout.bin"
	if err := preflightRunLocalOutputs(path, "", []string{"remote.out=local.out"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("preflight should not create the final capture file")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestPreflightRunLocalOutputsAllowsDownloadMissingDirs(t *testing.T) {
	root := t.TempDir()
	path := root + "/missing/nested/out.bin"
	if err := preflightRunLocalOutputs("", "", []string{"remote.out=" + path}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root + "/missing"); err == nil {
		t.Fatal("preflight should not create download directories")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestPreflightRunLocalOutputsDoesNotTruncateExistingDownloadFile(t *testing.T) {
	path := t.TempDir() + "/out.bin"
	if err := os.WriteFile(path, []byte("keep"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := preflightRunLocalOutputs("", "", []string{"remote.out=" + path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("download file was modified: %q", got)
	}
}

func TestPreflightRunLocalOutputsDoesNotTruncateExistingCaptureFile(t *testing.T) {
	path := t.TempDir() + "/stdout.bin"
	if err := os.WriteFile(path, []byte("keep"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := preflightRunLocalOutputs(path, "", nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("capture file was modified: %q", got)
	}
}

func TestPreflightRunLocalOutputsRejectsEquivalentCapturePaths(t *testing.T) {
	dir := t.TempDir()
	if err := preflightRunLocalOutputs(filepath.Join(dir, "run.log"), "", nil); err != nil {
		t.Fatal(err)
	}
	if err := preflightRunLocalOutputs(filepath.Join(dir, ".", "run.log"), filepath.Join(dir, "run.log"), nil); err == nil {
		t.Fatal("expected equivalent capture paths to fail")
	}
}

func TestPreflightRunLocalOutputsRejectsCaptureDownloadPathCollisions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.log")

	for _, tc := range []struct {
		name          string
		captureStdout string
		captureStderr string
	}{
		{name: "stdout", captureStdout: filepath.Join(dir, ".", "run.log")},
		{name: "stderr", captureStderr: filepath.Join(dir, ".", "run.log")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := preflightRunLocalOutputs(tc.captureStdout, tc.captureStderr, []string{"remote.out=" + path})
			if err == nil {
				t.Fatal("expected capture/download collision to fail")
			}
			if !strings.Contains(err.Error(), "paths must be different") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestPreflightRunLocalOutputsRejectsDuplicateDownloadTargets(t *testing.T) {
	dir := t.TempDir()
	err := preflightRunLocalOutputs("", "", []string{
		"first.out=" + filepath.Join(dir, "artifacts", "run.log"),
		"second.out=" + filepath.Join(dir, "artifacts", ".", "run.log"),
	})
	if err == nil {
		t.Fatal("expected duplicate download target to fail")
	}
	if !strings.Contains(err.Error(), "paths must be different") {
		t.Fatalf("err=%v", err)
	}
}

func TestRemoteDownloadBase64CommandPOSIX(t *testing.T) {
	got := remoteDownloadBase64Command(SSHTarget{}, "/work/repo", "out/sixel.bin")
	for _, want := range []string{
		"cd '/work/repo'",
		"test -f 'out/sixel.bin'",
		"base64 < 'out/sixel.bin'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("command missing %q in %q", want, got)
		}
	}
}

func TestRemoteDownloadBase64CommandWindows(t *testing.T) {
	got := remoteDownloadBase64Command(SSHTarget{TargetOS: targetWindows, WindowsMode: windowsModeNormal}, `C:\crabbox\repo`, `out\sixel.bin`)
	decoded := decodePowerShellCommand(t, got)
	for _, want := range []string{
		`Set-Location -LiteralPath 'C:\crabbox\repo'`,
		`$path = 'out\sixel.bin'`,
		`[System.IO.File]::ReadAllBytes`,
		`[Convert]::ToBase64String`,
	} {
		if !strings.Contains(decoded, want) {
			t.Fatalf("command missing %q in %q", want, decoded)
		}
	}
}
