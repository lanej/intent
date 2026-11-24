//go:build darwin

package activation

import (
	"errors"
	"fmt"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

func processIdentity(pid int) (string, error) {
	if pid <= 0 || pid > math.MaxInt32 {
		return "", errors.New("invalid SSH process")
	}

	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", err
	}

	if int(info.Proc.P_pid) != pid || int64(info.Eproc.Ucred.Uid) != int64(os.Getuid()) {
		return "", errors.New("SSH process is absent or not owned")
	}

	return fmt.Sprintf("%d-%d", info.Proc.P_starttime.Sec, info.Proc.P_starttime.Usec), nil
}
