// Package cleanup performs best-effort teardown after an outcome is determined.
// Unexpected failures are logged; callers must handle errors from writes, protocol
// operations, and authority-changing effects directly.
package cleanup

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
)

func Close(c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		log.Printf("close during cleanup: %v", err)
	}
}

func Remove(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("remove during cleanup: %v", err)
	}
}

func RemoveAll(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.Printf("remove directory during cleanup: %v", err)
	}
}
