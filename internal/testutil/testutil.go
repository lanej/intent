// Package testutil reports failures in asynchronous test operations and cleanup.
package testutil

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
)

func Check(t testing.TB, err error) {
	t.Helper()

	if err != nil {
		t.Error(err)
	}
}

// Close accepts transports already closed by cancellation, but reports other
// cleanup failures. It does not conceal read, write, or protocol errors.
func Close(t testing.TB, c io.Closer) {
	t.Helper()

	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		t.Error(err)
	}
}
