//go:build windows

package activation

import (
	"context"
	"errors"
)

func Call(context.Context, string, Request) (Result, error) {
	return Result{}, errors.New("approval lifecycle requires Unix sockets")
}
