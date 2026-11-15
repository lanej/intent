package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"runtime"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalssh"
)

type decisionExit struct{ code int }

func (e decisionExit) Error() string { return "approval not granted" }

func approvalCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: intent request --reason TEXT [--timeout 2m]")
	}

	switch args[0] {
	case "ssh-hook", "ssh-broker":
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)

		control := f.String("control", "", "absolute private OpenSSH control socket")
		if err := f.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}

			return err
		}

		if *control == "" || f.NArg() != 0 {
			return errors.New("SSH hook requires --control SOCKET")
		}

		if runtime.GOOS != "darwin" {
			return errors.New("automatic native approval must start on the Mac")
		}

		if args[0] == "ssh-hook" {
			return approvalssh.SSHHook(ctx, *control)
		}

		return approvalssh.RunHookBroker(ctx, *control)
	case "request":
		f := flag.NewFlagSet("approval request", flag.ContinueOnError)
		reason := f.String("reason", "", "action to review on the Mac")
		agentType := f.String("agent-type", "", "caller-supplied agent family; requires --agent-id")
		agentID := f.String("agent-id", "", "caller-supplied agent session/instance ID; requires --agent-type")

		timeout := f.Duration("timeout", approval.DefaultTimeout, "request lifetime (maximum 2m)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}

		if f.NArg() != 0 || *timeout <= 0 || *timeout > approval.DefaultTimeout {
			return errors.New("request requires --reason and a timeout between 0 and 2m")
		}

		explicitAgent := false

		f.Visit(func(flag *flag.Flag) {
			if flag.Name == "agent-type" || flag.Name == "agent-id" {
				explicitAgent = true
			}
		})

		agent, err := requestAgent(*agentType, *agentID, explicitAgent, os.Getenv)
		if err != nil {
			return err
		}

		client, err := approval.ClientFromEnv()
		if err != nil {
			return err
		}

		requestCtx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()

		result, err := client.Approve(requestCtx, approval.Request{Reason: *reason, Agent: agent})
		if err != nil {
			return err
		}

		if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}

		switch result.Decision {
		case approval.Approved:
			return nil
		case approval.Denied:
			return decisionExit{2}
		case approval.Cancelled:
			return decisionExit{3}
		case approval.TimedOut:
			return decisionExit{4}
		case approval.Unavailable:
			return decisionExit{5}
		case approval.Busy:
			return decisionExit{6}
		default:
			return errors.New("invalid approval decision")
		}
	case "session":
		if len(args) == 3 && args[1] == "prepare" {
			return approvalssh.Prepare(args[2], os.Stdout)
		}

		if len(args) == 4 {
			if args[1] == "publish" {
				return approvalssh.Publish(args[2], args[3])
			}

			if args[1] == "cleanup" {
				return approvalssh.Cleanup(args[2], args[3])
			}

			if args[1] == "shell" {
				return approvalssh.Shell(ctx, args[2], args[3])
			}
		}
	}

	return errors.New("invalid approval command")
}

func sshApprovalCommand(ctx context.Context, args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("start intent ssh from the Mac providing native approval")
	}

	if len(args) != 1 {
		return errors.New("usage: intent ssh HOST")
	}

	return approvalssh.Launch(ctx, args[0])
}
