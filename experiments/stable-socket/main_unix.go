//go:build !windows

// The proof is deliberately outside cmd/intent and is never installed by Make.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lanej/intent/internal/approvalssh"
	"github.com/lanej/intent/internal/approvalwire"
	local "github.com/lanej/intent/internal/intent"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:], local.Native()); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
			os.Exit(2)
		}

		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, authenticate local.Authenticate) error {
	if len(args) == 0 {
		return errors.New("proof: broker|connect|prepare|register; see README.md")
	}

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := flags.String("dir", "", "absolute private stable broker directory on remote host")
	mac := flags.String("mac", "", "explicit paired Mac ID (32 hexadecimal characters; routing identity, not authentication)")
	session := flags.String("session", "", "private transport ID")
	upstream := flags.String("upstream", "", "private forwarded transport socket")
	config := flags.String("ssh-config", "", "explicit audited SSH configuration file for this proof")

	remote := flags.String("remote-binary", "intent-socket-proof", "proof binary on remote noninteractive PATH")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	switch args[0] {
	case "prepare":
		return approvalssh.Prepare(*session, os.Stdout)
	case "cleanup":
		return approvalssh.Cleanup(*session, *upstream)
	case "broker":
		if !approvalwire.ValidID(*mac) {
			return errors.New("explicit paired Mac ID required")
		}

		return serveBroker(ctx, *dir, *mac)
	case "register":
		return register(ctx, *dir, registration{Version: 1, Mac: *mac, Session: *session, Socket: *upstream})
	case "connect":
		if flags.NArg() != 1 || !approvalwire.ValidID(*mac) {
			return errors.New("connect requires --dir DIR --mac ID HOST")
		}

		return connect(ctx, *config, flags.Arg(0), *remote, *dir, *mac, authenticate)
	default:
		return errors.New("unsupported proof command")
	}
}
