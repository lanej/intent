//go:build windows

package approvalconfig

import (
	"context"
	"errors"
)

func unsupported() error                                      { return errors.New("SSH forwarding configuration requires Unix") }
func Configure(context.Context, string, string, string) error { return unsupported() }
func Prepare(context.Context, string, int) error              { return unsupported() }
func Match(int, string) error                                 { return unsupported() }
func Connected(context.Context, string) error                 { return unsupported() }
func Serve(context.Context, string) error                     { return unsupported() }

func Install(context.Context, string, string) error { return unsupported() }
