//go:build windows

package approvalssh

import (
	"context"
	"errors"
	"io"
)

var errUnsupported = errors.New("SSH approval requires macOS or Linux")

func Launch(context.Context, string) error        { return errUnsupported }
func Prepare(string, io.Writer) error             { return errUnsupported }
func Cleanup(string, string) error                { return errUnsupported }
func Shell(context.Context, string, string) error { return errUnsupported }
func Publish(string, string) error                { return errUnsupported }
func SSHHook(context.Context, string) error       { return errUnsupported }
func RunHookBroker(context.Context, string) error { return errUnsupported }
