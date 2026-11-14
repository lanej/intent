//go:build windows

package approvaldiscovery

import "errors"

type Receipt struct {
	Version int
	Session string
	Socket  string
}

func Read() (Receipt, error) {
	return Receipt{}, errors.New("SSH approval discovery requires macOS or Linux")
}
func Path() (string, error)            { return "", errors.New("SSH approval discovery requires macOS or Linux") }
func ReadPath(string) (Receipt, error) { return Read() }
