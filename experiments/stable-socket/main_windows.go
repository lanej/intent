//go:build windows

package main

import (
	"fmt"
	"os"
)

func main() {
	if _, err := fmt.Fprintln(os.Stderr, "The stable socket proof requires Unix-domain sockets and OpenSSH"); err != nil {
		os.Exit(2)
	}

	os.Exit(1)
}
