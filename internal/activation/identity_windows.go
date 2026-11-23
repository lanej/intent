//go:build windows

package activation

import "errors"

func processIdentity(int) (string, error) {
	return "", errors.New("approval process identity requires macOS or Linux")
}
