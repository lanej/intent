//go:build !windows

package cleanup

import (
	"log"
	"syscall"
)

// Unlock is followed by descriptor closure, which also releases the lock.
func Unlock(fd int) {
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		log.Printf("unlock during cleanup: %v", err)
	}
}
