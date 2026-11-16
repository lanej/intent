//go:build linux

package approvalconfig

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

func processIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("invalid SSH process")
	}
	path := fmt.Sprintf("/proc/%d/stat", pid)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Getuid()) {
		return "", errors.New("SSH process is not owned")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- The path is derived solely from a positive numeric process ID under /proc.
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end == -1 {
		return "", errors.New("invalid process identity")
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return "", errors.New("invalid process identity")
	}
	boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if bootErr != nil {
		return "", bootErr
	}
	return strings.TrimSpace(string(boot)) + "-" + fields[19], nil
}
