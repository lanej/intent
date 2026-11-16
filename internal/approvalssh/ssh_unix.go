//go:build !windows

// Package approvalssh owns session-scoped SSH forwarding and its remote helper.
package approvalssh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/cleanup"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/intent"
)

type prepared struct {
	Version int    `json:"version"`
	Socket  string `json:"socket"`
}

func validHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "-") || len(host) > 1024 {
		return false
	}

	for _, c := range host {
		if c <= 32 || c == 127 {
			return false
		}
	}

	return true
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// Launch uses the installed OpenSSH client, including its host aliases and auth.
// It owns a fresh master instead of extending an unrelated multiplexed session.
func Launch(ctx context.Context, host string) error {
	return launch(ctx, host, intent.Native())
}

func launch(ctx context.Context, host string, authenticate intent.Authenticate) error {
	if !validHost(host) {
		return errors.New("usage: intent ssh HOST (configure ports and jumps in ~/.ssh/config)")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	session := hex.EncodeToString(nonce)

	dir, err := os.MkdirTemp("/tmp", "intent-ssh-")
	if err != nil {
		return err
	}
	defer cleanup.RemoveAll(dir)

	socket := filepath.Join(dir, "approval.sock")

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer cleanup.Close(listener)

	if err = os.Chmod(socket, 0o600); err != nil {
		return err
	}

	serviceCtx, stopService := context.WithCancel(ctx)
	serviceDone := make(chan error, 1)

	service := &intent.Service{Host: host, Session: session, Authenticate: authenticate}
	go func() { serviceDone <- service.Serve(serviceCtx, listener) }()

	defer func() { stopService(); cleanup.Close(listener); <-serviceDone }()

	control := filepath.Join(dir, "control")

	masterCtx, stopMaster := context.WithCancel(ctx)
	defer stopMaster()

	master := exec.CommandContext(masterCtx, "ssh", "-M", "-N", "-S", control, "-o", "PermitLocalCommand=no", "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no", "-o", "ExitOnForwardFailure=yes", "-o", "ClearAllForwardings=yes", "-o", "RemoteCommand=none", "--", host) // #nosec G204 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.

	master.Stdin, master.Stdout, master.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = master.Start(); err != nil {
		return err
	}

	masterDone := make(chan struct{})

	var masterErr error
	go func() { masterErr = master.Wait(); close(masterDone) }()

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()

		if cleanupErr := exec.CommandContext(cleanupCtx, "ssh", "-S", control, "-O", "exit", "--", host).Run(); cleanupErr != nil { // #nosec G204 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.
			log.Print("intent: SSH mux exit unavailable; stopping owned master")
		}

		stopMaster()
		<-masterDone
	}()
	// A stopped master cancels any open approval even if the remote shell process
	// has not yet noticed the broken transport.
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	// Polling the private control endpoint never initiates a fallback connection.
	readyCtx, cancelReady := context.WithTimeout(sessionCtx, 2*time.Minute)
	defer cancelReady()

	for exec.CommandContext(readyCtx, "ssh", "-S", control, "-O", "check", "--", host).Run() != nil { // #nosec G204 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.
		select {
		case <-masterDone:
			return fmt.Errorf("SSH master exited before setup: %w", masterErr)
		case <-readyCtx.Done():
			return fmt.Errorf("SSH setup: %w", readyCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}

	go func() { <-masterDone; stopService(); cancelSession() }()
	// Disable fallback connections for every channel: if the master disappears,
	// ProxyCommand=false fails closed rather than starting another SSH transport.
	run := func(c context.Context, tty bool, args ...string) *exec.Cmd {
		options := []string{"-S", control, "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "ProxyCommand=false", "-o", "RemoteCommand=none"}
		if tty {
			options = append(options, "-tt")
		} else {
			options = append(options, "-T")
		}

		command := "intent session"
		for _, a := range args {
			command += " " + quote(a)
		}

		options = append(options, "--", host, command)

		return exec.CommandContext(c, "ssh", options...) // #nosec G204 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.
	}
	prepare := run(sessionCtx, false, "prepare", session)

	var output limitedOutput

	prepare.Stdout = &output

	prepare.Stderr = os.Stderr
	if err = prepare.Run(); err != nil {
		return fmt.Errorf("remote approval endpoint preparation: %w", err)
	}

	var remote prepared
	if err = json.Unmarshal(output.data, &remote); err != nil || remote.Version != 1 || !validRemoteSocket(remote.Socket) {
		return errors.New("invalid remote approval endpoint")
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()

		cleanup := run(cleanupCtx, false, "cleanup", session, remote.Socket)
		if runErr := cleanup.Run(); runErr != nil {
			log.Printf("intent: remote cleanup unavailable; retained endpoint directory %s\n", filepath.Dir(remote.Socket))
		}
	}()
	// Teardown must disable requests before remote cleanup can block. Background
	// remote processes must not create prompts after the shell has exited.
	defer stopService()

	// Use only the explicit approval forward; host configuration may add unrelated endpoints.
	forward := exec.CommandContext(sessionCtx, "ssh", "-F", "/dev/null", "-S", control, "-O", "forward", "-o", "ClearAllForwardings=no", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=no", "-R", remote.Socket+":"+socket, "--", host) // #nosec G204 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.

	forward.Stderr = os.Stderr
	if err = forward.Run(); err != nil {
		return fmt.Errorf("approval forwarding: %w", err)
	}

	shell := run(sessionCtx, true, "shell", session, remote.Socket)
	shell.Stdin, shell.Stdout, shell.Stderr = os.Stdin, os.Stdout, os.Stderr

	return shell.Run()
}

type limitedOutput struct{ data []byte }

func (o *limitedOutput) Write(p []byte) (int, error) {
	if len(o.data)+len(p) > 4096 {
		return 0, errors.New("remote setup output too large")
	}

	o.data = append(o.data, p...)

	return len(p), nil
}

func validRemoteSocket(socket string) bool {
	dir := filepath.Dir(socket)
	return filepath.Base(socket) == "approval.sock" && filepath.Dir(dir) == "/tmp" && strings.HasPrefix(filepath.Base(dir), "intent-approval-") && filepath.Clean(socket) == socket
}

func checkRemote(session, socket string) error {
	if !approvalwire.ValidID(session) || !validRemoteSocket(socket) {
		return errors.New("invalid approval session endpoint")
	}

	dir := filepath.Dir(socket)

	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || int64(stat.Uid) != int64(os.Getuid()) {
		return errors.New("approval session directory is not private and owned")
	}

	marker := filepath.Join(dir, "session")

	info, err = os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("invalid approval session marker")
	}

	data, err := os.ReadFile(marker) // #nosec G304 -- The path is derived from the validated private SSH session or owned hook directory.
	if err != nil || string(data) != session {
		return errors.New("approval session ownership mismatch")
	}

	return nil
}

func Prepare(session string, out io.Writer) error {
	if !approvalwire.ValidID(session) {
		return errors.New("invalid approval session")
	}

	dir, err := os.MkdirTemp("/tmp", "intent-approval-")
	if err != nil {
		return err
	}

	if err = os.WriteFile(filepath.Join(dir, "session"), []byte(session), 0o600); err != nil {
		cleanup.RemoveAll(dir)
		return err
	}

	err = json.NewEncoder(out).Encode(prepared{Version: 1, Socket: filepath.Join(dir, "approval.sock")})
	if err != nil {
		cleanup.RemoveAll(dir)
	}

	return err
}

func Publish(session, socket string) error {
	if err := checkRemote(session, socket); err != nil {
		return err
	}

	return approvaldiscovery.PublishWithCleanup(approvaldiscovery.Receipt{Version: 1, Session: session, Socket: socket}, pruneStaleApprovals)
}

func Cleanup(session, socket string) error {
	if err := cleanupEndpoint(session, socket); err != nil {
		return err
	}

	return approvaldiscovery.Remove(session)
}

func cleanupEndpoint(session, socket string) error {
	if !approvalwire.ValidID(session) || !validRemoteSocket(socket) {
		return errors.New("invalid approval session endpoint")
	}

	if _, err := os.Lstat(filepath.Dir(socket)); os.IsNotExist(err) {
		return nil
	}

	if err := checkRemote(session, socket); err != nil {
		return err
	}

	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to remove non-socket approval endpoint")
		}

		if err = os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.Remove(filepath.Join(filepath.Dir(socket), "session")); err != nil {
		return err
	}

	return os.Remove(filepath.Dir(socket))
}

func Shell(ctx context.Context, session, socket string) error {
	if err := checkRemote(session, socket); err != nil {
		return err
	}
	defer func() {
		if err := Cleanup(session, socket); err != nil {
			log.Printf("intent: remote cleanup: %v\n", err)
		}
	}()

	shell := os.Getenv("SHELL")
	if !filepath.IsAbs(shell) {
		shell = "/bin/sh"
	}

	cmd := exec.CommandContext(ctx, shell, "-l") // #nosec G204 G702 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.

	cmd.Env = append(os.Environ(), approval.SocketEnv+"="+socket)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	return cmd.Run()
}
