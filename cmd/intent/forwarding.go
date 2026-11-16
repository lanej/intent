package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/lanej/intent/internal/approvalconfig"
	"github.com/lanej/intent/internal/approvalforward"
)

func forwardingCommand(ctx context.Context, args []string) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	profile := f.String("profile", "", "absolute private SSH profile JSON")
	parent := f.Int("parent", 0, "SSH configuration parser process")
	identity := f.String("identity", "", "SSH parser start identity")
	dir := f.String("directory", "", "absolute private remote socket directory")
	mac := f.String("mac-id", "", "explicitly paired Mac routing ID")
	config := f.String("ssh-config", "", "SSH config file (default ~/.ssh/config)")
	host := f.String("host", "", "literal SSH host alias")

	executable := f.String("executable", "", "absolute installed Intent executable")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}

	if f.NArg() != 0 {
		return errors.New("unexpected forwarding arguments")
	}

	switch args[0] {
	case "configure-ssh":
		if *executable == "" {
			path, err := os.Executable()
			if err != nil {
				return err
			}

			*executable = path
		}

		if err := approvalconfig.Configure(ctx, *host, *dir, *executable); err != nil {
			return err
		}

		return approvalconfig.Install(ctx, *host, *config)
	case "ssh-prepare":
		return approvalconfig.Prepare(ctx, *profile, *parent)
	case "ssh-match":
		return approvalconfig.Match(*parent, *identity)
	case "ssh-connected":
		return approvalconfig.Connected(ctx, *profile)
	case "serve-local":
		return approvalconfig.Serve(ctx, *profile)
	case "serve-remote":
		return approvalforward.ServeRemote(ctx, *dir, *mac)
	default:
		return errors.New("invalid forwarding command")
	}
}
