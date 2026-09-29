package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsolateUserDirsContainsStateAndPlatformConfig(t *testing.T) {
	dirs := IsolateUserDirs(t)

	if got := os.Getenv("XDG_STATE_HOME"); got != dirs.StateHome {
		t.Fatalf("XDG_STATE_HOME=%q want %q", got, dirs.StateHome)
	}
	if got := os.Getenv("APPDATA"); got != dirs.AppData {
		t.Fatalf("APPDATA=%q want %q", got, dirs.AppData)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := requireWithinRoot(dirs.Root, configDir); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && configDir != dirs.AppData {
		t.Fatalf("Windows user config directory=%q want APPDATA %q", configDir, dirs.AppData)
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{dirs.Root, dirs.Home, dirs.ConfigHome, dirs.StateHome, dirs.AppData} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("isolated user directory %q mode=%#o want private", path, info.Mode().Perm())
			}
		}
	}
	stateDir := filepath.Join(os.Getenv("XDG_STATE_HOME"), "crabbox")
	if err := requireWithinRoot(dirs.Root, stateDir); err != nil {
		t.Fatal(err)
	}
}
