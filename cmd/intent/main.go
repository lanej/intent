package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		var decision decisionExit
		if errors.As(err, &decision) {
			os.Exit(decision.code)
		}

		if _, writeErr := fmt.Fprintln(os.Stderr, "intent:", err); writeErr != nil {
			os.Exit(1)
		}

		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		_, err := fmt.Println("Intent: explicit human approval over SSH\n\nintent request --reason TEXT [--timeout 2m]\nintent ssh HOST\nintent ssh-hook --control SOCKET\n\nA confirmed approval reports intent; callers own action enforcement.")
		return err
	}

	if args[0] == "ssh" {
		return sshApprovalCommand(ctx, args[1:])
	}

	return approvalCommand(ctx, args)
}
