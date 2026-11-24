//go:build !darwin && !linux && !windows

package activation

import "errors"

func processIdentity(int) (string, error) {
	return "", errors.New("SSH preparation requires macOS or Linux")
}
