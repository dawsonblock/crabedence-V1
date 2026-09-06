//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

func configureDaemonCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func stopDaemonProcess(process *os.Process, pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return process.Kill()
	}
	return nil
}
