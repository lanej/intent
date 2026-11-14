//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
	local "github.com/lanej/intent/internal/intent"
)

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > approvalwire.MaxFrame {
		return 0, errors.New("remote setup output exceeds bound")
	}

	return b.Buffer.Write(data)
}

func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func sshCommand(ctx context.Context, config, host string, extra []string, remote string, args ...string) *exec.Cmd {
	options := []string{"-F", config, "-T", "-S", "none", "-o", "ControlMaster=no", "-o", "ControlPersist=no", "-o", "PermitLocalCommand=no", "-o", "ForwardAgent=no", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "RemoteCommand=none"}
	options = append(options, extra...)

	command := quote(remote)
	for _, arg := range args {
		command += " " + quote(arg)
	}

	options = append(options, "--", host, command)

	return exec.CommandContext(ctx, "ssh", options...) // #nosec G204 G702 -- Fixed SSH executable and argv; every remote command argument is shell-quoted.
}

func connect(ctx context.Context, config, host, remote, dir, mac string, authenticate local.Authenticate) error {
	if host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, "\r\n\x00") {
		return errors.New("invalid SSH host")
	}

	if !filepath.IsAbs(config) || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("explicit SSH config and remote broker directory must be absolute")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	session := hex.EncodeToString(nonce)

	setup, stopSetup := context.WithTimeout(ctx, 20*time.Second)
	defer stopSetup()

	prepare := sshCommand(setup, config, host, []string{"-o", "ClearAllForwardings=yes"}, remote, "prepare", "--session", session)

	var output limitedBuffer

	prepare.Stdout = &output

	prepare.Stderr = os.Stderr
	if err := prepare.Run(); err != nil {
		return fmt.Errorf("prepare transport: %w", err)
	}

	var endpoint struct {
		Version int    `json:"version"`
		Socket  string `json:"socket"`
	}
	if err := json.Unmarshal(output.Bytes(), &endpoint); err != nil {
		return err
	}
	// Only the existing remote helper's private layout is allowed in -R syntax.
	parent := filepath.Base(filepath.Dir(endpoint.Socket))
	if endpoint.Version != 1 || filepath.Dir(filepath.Dir(endpoint.Socket)) != "/tmp" || filepath.Base(endpoint.Socket) != "approval.sock" || !strings.HasPrefix(parent, "intent-approval-") || strings.ContainsAny(endpoint.Socket, ":\r\n\x00") {
		return errors.New("invalid prepared endpoint")
	}

	forwardStarted := false
	defer func() {
		if forwardStarted {
			return
		}

		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()

		command := sshCommand(cleanupCtx, config, host, []string{"-o", "ClearAllForwardings=yes"}, remote, "cleanup", "--session", session, "--upstream", endpoint.Socket)

		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			logCleanup(endpoint.Socket, err)
		}
	}()

	dirLocal, err := os.MkdirTemp("/tmp", "intent-proof-")
	if err != nil {
		return err
	}
	defer cleanup.RemoveAll(dirLocal)

	socket := filepath.Join(dirLocal, "approval.sock")

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer cleanup.Close(listener)

	if err = os.Chmod(socket, 0o600); err != nil {
		return err
	}

	serviceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	service := &local.Service{Host: host, Session: session, Authenticate: authenticate}

	finished := make(chan error, 1)
	go func() { finished <- service.Serve(serviceCtx, listener) }()

	defer func() {
		cancel()
		cleanup.Close(listener)

		if serviceErr := <-finished; serviceErr != nil {
			logCleanup(socket, serviceErr)
		}
	}()
	// A dedicated config makes inherited forwards reviewable. ClearAllForwardings
	// must be no here: yes would also erase this command's explicit -R.
	command := sshCommand(serviceCtx, config, host, []string{"-o", "ClearAllForwardings=no", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=no", "-R", endpoint.Socket + ":" + socket}, remote,
		"register", "--dir", dir, "--mac", mac, "--session", session, "--upstream", endpoint.Socket)

	input, err := command.StdinPipe()
	if err != nil {
		return err
	}
	defer cleanup.Close(input)

	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err = command.Start(); err != nil {
		return err
	}

	forwardStarted = true

	return command.Wait()
}

func logCleanup(path string, err error) {
	if _, writeErr := fmt.Fprintf(os.Stderr, "proof cleanup may remain at %s: %v\n", path, err); writeErr != nil {
		return
	}
}
