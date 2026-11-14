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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "approval.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	serviceCtx, stopService := context.WithCancel(ctx)
	serviceDone := make(chan error, 1)
	service := &intent.Service{Host: host, Session: session, Authenticate: authenticate}
	go func() { serviceDone <- service.Serve(serviceCtx, listener) }()
	defer func() { stopService(); _ = listener.Close(); <-serviceDone }()
	control := filepath.Join(dir, "control")
	masterCtx, stopMaster := context.WithCancel(ctx)
	defer stopMaster()
	master := exec.CommandContext(masterCtx, "ssh", "-M", "-N", "-S", control, "-o", "PermitLocalCommand=no", "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no", "-o", "ExitOnForwardFailure=yes", "-o", "ClearAllForwardings=yes", "-o", "RemoteCommand=none", "--", host)
	master.Stdin, master.Stdout, master.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = master.Start(); err != nil {
		return err
	}
	masterDone := make(chan struct{})
	var masterErr error
	go func() { masterErr = master.Wait(); close(masterDone) }()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanupCtx, "ssh", "-S", control, "-O", "exit", "--", host).Run()
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
	for exec.CommandContext(readyCtx, "ssh", "-S", control, "-O", "check", "--", host).Run() != nil {
		select {
		case <-masterDone:
			return fmt.Errorf("SSH master exited before setup: %v", masterErr)
		case <-readyCtx.Done():
			return fmt.Errorf("SSH setup: %w", readyCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	go func() { <-masterDone; stopService(); cancelSession() }()
	// Disable fallback connections for every channel: if the master disappears,
	// ProxyCommand=false fails closed rather than starting another SSH transport.
	run := func(c context.Context, tty bool, args ...string) *exec.Cmd {
		options := []string{"-S", control, "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ProxyCommand=false", "-o", "RemoteCommand=none"}
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
		return exec.CommandContext(c, "ssh", options...)
	}
	prepare := run(sessionCtx, false, "prepare", session)
	var output limitedOutput
	prepare.Stdout = &output
	prepare.Stderr = os.Stderr
	if err = prepare.Run(); err != nil {
		return fmt.Errorf("remote approval setup (install Intent on remote PATH): %w", err)
	}
	var remote prepared
	if err = json.Unmarshal(output.data, &remote); err != nil || remote.Version != 1 || !validRemoteSocket(remote.Socket) {
		return errors.New("invalid remote approval endpoint")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cleanup := run(cleanupCtx, false, "cleanup", session, remote.Socket)
		if err := cleanup.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "intent: remote cleanup unavailable; retained endpoint directory %s\n", filepath.Dir(remote.Socket))
		}
	}()
	// Teardown must disable requests before remote cleanup can block. Background
	// remote processes must not create prompts after the shell has exited.
	defer stopService()
	forward := exec.CommandContext(sessionCtx, "ssh", "-S", control, "-O", "forward", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=no", "-R", remote.Socket+":"+socket, "--", host)
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
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Getuid()) {
		return errors.New("approval session directory is not private and owned")
	}
	marker := filepath.Join(dir, "session")
	info, err = os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("invalid approval session marker")
	}
	data, err := os.ReadFile(marker)
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
	if err = os.WriteFile(filepath.Join(dir, "session"), []byte(session), 0600); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	err = json.NewEncoder(out).Encode(prepared{Version: 1, Socket: filepath.Join(dir, "approval.sock")})
	if err != nil {
		_ = os.RemoveAll(dir)
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
			fmt.Fprintf(os.Stderr, "intent: remote cleanup: %v\n", err)
		}
	}()
	shell := os.Getenv("SHELL")
	if !filepath.IsAbs(shell) {
		shell = "/bin/sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-l")
	cmd.Env = append(os.Environ(), approval.SocketEnv+"="+socket)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
