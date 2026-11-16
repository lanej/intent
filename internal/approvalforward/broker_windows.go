//go:build windows

package approvalforward

import (
	"context"
	"errors"
)

func ServeRemote(context.Context, string, string) error {
	return errors.New("remote approval broker requires Unix sockets")
}
