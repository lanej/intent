//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalssh"
	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
	local "github.com/lanej/intent/internal/intent"
	"github.com/lanej/intent/internal/testutil"
)

const pairedMac = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// The synthetic callback exists only in the test executable, not the proof CLI.
func TestMain(m *testing.M) {
	if os.Getenv("INTENT_SOCKET_PROOF_HELPER") == "1" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		authenticate := func(ctx context.Context, p local.Prompt) approval.Decision {
			switch p.Reason {
			case "proof approve":
				return approval.Approved
			case "proof pending":
				marker := os.Getenv("INTENT_PROOF_STARTED")
				if err := os.WriteFile(marker, []byte("pending"), 0o600); err != nil { // #nosec G703 -- Marker path is supplied only by the disposable test fixture.
					return approval.Unavailable
				}

				<-ctx.Done()

				if err := os.WriteFile(marker+".cancelled", []byte("cancelled"), 0o600); err != nil { // #nosec G703 -- Marker path is supplied only by the disposable test fixture.
					return approval.Unavailable
				}

				return approval.Approved // Deliberate late success must never escape cancellation.
			default:
				return approval.Denied
			}
		}
		if err := run(ctx, os.Args[1:], authenticate); err != nil && ctx.Err() == nil {
			if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
				os.Exit(2)
			}

			os.Exit(1)
		}

		os.Exit(0)
	}

	os.Exit(m.Run())
}

func temporary(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "intent-proof-test-") //nolint:usetesting // Unix-domain socket fixtures require a short path on macOS.
	testutil.Check(t, err)
	t.Cleanup(func() { testutil.Check(t, os.RemoveAll(dir)) })

	return dir
}

func eventually(t *testing.T, description string, ready func() bool) {
	t.Helper()

	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if ready() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("timed out: " + description)
}

func startBroker(t *testing.T, dir string) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serveBroker(ctx, dir, pairedMac) }()

	t.Cleanup(func() { cancel(); testutil.Check(t, <-done) })
	eventually(t, "broker sockets", func() bool { _, err := os.Stat(filepath.Join(dir, "registration.sock")); return err == nil })
}

func preparedRoute(t *testing.T, session string, decision approval.Decision) registration {
	t.Helper()

	var output bytes.Buffer
	testutil.Check(t, approvalssh.Prepare(session, &output))

	var endpoint struct {
		Socket string `json:"socket"`
	}
	testutil.Check(t, json.Unmarshal(output.Bytes(), &endpoint))

	ctx, cancel := context.WithCancel(context.Background())
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", endpoint.Socket)
	testutil.Check(t, err)
	testutil.Check(t, os.Chmod(endpoint.Socket, 0o600))

	done := make(chan error, 1)

	service := &local.Service{Authenticate: func(context.Context, local.Prompt) approval.Decision { return decision }}
	go func() { done <- service.Serve(ctx, listener) }()

	t.Cleanup(func() {
		cancel()
		cleanup.Close(listener)
		testutil.Check(t, <-done)
		testutil.Check(t, approvalssh.Cleanup(session, endpoint.Socket))
	})

	return registration{Version: 1, Mac: pairedMac, Session: session, Socket: endpoint.Socket}
}

func registerRoute(t *testing.T, dir string, r registration) (net.Conn, acknowledgment) {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", filepath.Join(dir, "registration.sock"))
	testutil.Check(t, err)
	t.Cleanup(func() { cleanup.Close(conn) })
	testutil.Check(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	testutil.Check(t, json.NewEncoder(conn).Encode(r))

	var ack acknowledgment
	testutil.Check(t, approvalwire.Read(conn, &ack))

	return conn, ack
}

func expectDecision(t *testing.T, socket, reason string, want approval.Decision) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := approval.NewClient(socket).Approve(ctx, approval.Request{Reason: reason})
	if err != nil || result.Decision != want {
		t.Fatalf("want %s, got %+v: %v", want, result, err)
	}
}

func TestStableSocketRouteOwnership(t *testing.T) {
	dir := temporary(t)
	startBroker(t, dir)
	socket := filepath.Join(dir, "approval.sock")
	original, err := os.Stat(socket)
	testutil.Check(t, err)
	expectDecision(t, socket, "no route", approval.Unavailable)
	a := preparedRoute(t, strings.Repeat("1", 32), approval.Approved)

	old, ack := registerRoute(t, dir, a)
	if ack.Error != "" {
		t.Fatal(ack.Error)
	}

	expectDecision(t, socket, "A", approval.Approved)
	b := preparedRoute(t, strings.Repeat("2", 32), approval.Denied)

	current, ack := registerRoute(t, dir, b)
	if ack.Error != "" {
		t.Fatal(ack.Error)
	}

	cleanup.Close(old)
	eventually(t, "old transport cleanup", func() bool { _, statErr := os.Stat(filepath.Dir(a.Socket)); return os.IsNotExist(statErr) })
	expectDecision(t, socket, "B", approval.Denied)

	if duplicateErr := register(t.Context(), dir, b); duplicateErr == nil {
		t.Fatal("duplicate endpoint registration accepted")
	}

	expectDecision(t, socket, "B survives duplicate disconnect", approval.Denied)
	foreign := preparedRoute(t, strings.Repeat("4", 32), approval.Approved)
	foreign.Mac = strings.Repeat("b", 32)

	_, ack = registerRoute(t, dir, foreign)
	if !strings.Contains(ack.Error, "different Mac") {
		t.Fatal("different Mac replaced paired route")
	}

	expectDecision(t, socket, "still B", approval.Denied)
	c := preparedRoute(t, strings.Repeat("3", 32), approval.Approved)

	newest, ack := registerRoute(t, dir, c)
	if ack.Error != "" {
		t.Fatal(ack.Error)
	}

	expectDecision(t, socket, "C", approval.Approved)

	if duplicateErr := register(t.Context(), dir, b); duplicateErr == nil {
		t.Fatal("displaced endpoint ownership was forgotten")
	}

	expectDecision(t, socket, "C survives displaced duplicate", approval.Approved)
	cleanup.Close(newest)
	eventually(t, "selected transport removal", func() bool { _, statErr := os.Stat(filepath.Dir(c.Socket)); return os.IsNotExist(statErr) })
	expectDecision(t, socket, "must not fall back to B", approval.Unavailable)
	cleanup.Close(current)
	eventually(t, "last older transport cleanup", func() bool { _, statErr := os.Stat(filepath.Dir(b.Socket)); return os.IsNotExist(statErr) })

	after, err := os.Stat(socket)
	testutil.Check(t, err)

	if !os.SameFile(original, after) {
		t.Fatal("stable public socket was replaced during handover")
	}
}

func helper(t *testing.T, args ...string) (*exec.Cmd, *json.Decoder) {
	t.Helper()

	exe, err := os.Executable()
	testutil.Check(t, err)

	cmd := exec.CommandContext(t.Context(), exe, args...) // #nosec G204 -- This executes the current test binary with fixture-owned argv.

	cmd.Env = append(os.Environ(), "INTENT_SOCKET_PROOF_HELPER=1")
	cmd.Stderr = os.Stderr
	output, err := cmd.StdoutPipe()
	testutil.Check(t, err)
	testutil.Check(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			if signalErr := cmd.Process.Signal(syscall.SIGTERM); signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
				t.Error(signalErr)
			}

			if waitErr := cmd.Wait(); waitErr != nil && t.Context().Err() == nil {
				t.Error(waitErr)
			}
		}
	})

	return cmd, json.NewDecoder(output)
}

func registered(t *testing.T, decoder *json.Decoder) {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		var ack acknowledgment

		err := decoder.Decode(&ack)
		if err == nil && (ack.Error != "" || !approvalwire.ValidID(ack.Session)) {
			err = errors.New("invalid registration acknowledgment")
		}

		done <- err
	}()

	select {
	case err := <-done:
		testutil.Check(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("SSH transport registration not acknowledged")
	}
}

func TestNoControlMasterOpenSSH(t *testing.T) {
	if os.Getenv("INTENT_SSH_INTEGRATION") != "1" {
		t.Skip("set INTENT_SSH_INTEGRATION=1 for real disposable SSH proof")
	}

	dir := temporary(t)
	brokerDir := filepath.Join(dir, "broker")
	startBroker(t, brokerDir)
	socket := filepath.Join(brokerDir, "approval.sock")
	original, err := os.Stat(socket)
	testutil.Check(t, err)
	config := startSSHD(t, dir)
	exe, err := os.Executable()
	testutil.Check(t, err)

	args := []string{"connect", "--ssh-config", config, "--remote-binary", exe, "--dir", brokerDir, "--mac", pairedMac, "proof"}
	oldMarker := filepath.Join(dir, "old-pending")
	t.Setenv("INTENT_PROOF_STARTED", oldMarker)
	first, decoder := helper(t, args...)
	registered(t, decoder)
	expectDecision(t, socket, "proof approve", approval.Approved)
	expectDecision(t, socket, "proof deny", approval.Denied)

	oldCtx, oldCancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer oldCancel()

	oldPending := make(chan error, 1)

	go func() {
		_, approveErr := approval.NewClient(socket).Approve(oldCtx, approval.Request{Reason: "proof pending"})
		oldPending <- approveErr
	}()

	eventually(t, "old callback pending", func() bool { _, statErr := os.Stat(oldMarker); return statErr == nil })

	marker := filepath.Join(dir, "pending")
	t.Setenv("INTENT_PROOF_STARTED", marker)
	second, decoder := helper(t, args...)
	registered(t, decoder)
	expectDecision(t, socket, "proof approve", approval.Approved)

	select {
	case pendingErr := <-oldPending:
		t.Fatalf("handover unexpectedly completed old request: %v", pendingErr)
	default:
	}

	testutil.Check(t, first.Process.Signal(syscall.SIGTERM))
	testutil.Check(t, first.Wait())

	select {
	case pendingErr := <-oldPending:
		if !errors.Is(pendingErr, approval.ErrOutcomeUnknown) {
			t.Fatalf("old request was replayed or lost uncertainty: %v", pendingErr)
		}
	case <-oldCtx.Done():
		t.Fatal("old request did not stop with its own transport")
	}

	eventually(t, "old callback cancelled", func() bool { _, statErr := os.Stat(oldMarker + ".cancelled"); return statErr == nil })
	expectDecision(t, socket, "proof approve", approval.Approved)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	pending := make(chan error, 1)

	go func() {
		_, approveErr := approval.NewClient(socket).Approve(ctx, approval.Request{Reason: "proof pending"})
		pending <- approveErr
	}()

	eventually(t, "native callback pending", func() bool { _, statErr := os.Stat(marker); return statErr == nil })
	testutil.Check(t, second.Process.Signal(syscall.SIGTERM))
	testutil.Check(t, second.Wait())

	select {
	case pendingErr := <-pending:
		if !errors.Is(pendingErr, approval.ErrOutcomeUnknown) {
			t.Fatalf("dropped in-flight request lost uncertainty: %v", pendingErr)
		}
	case <-ctx.Done():
		t.Fatal("pending request did not stop with transport")
	}

	eventually(t, "late approval cancelled", func() bool { _, statErr := os.Stat(marker + ".cancelled"); return statErr == nil })
	eventually(t, "route unavailable", func() bool {
		result, approveErr := approval.NewClient(socket).Approve(ctx, approval.Request{Reason: "no route"})
		return approveErr == nil && result.Decision == approval.Unavailable
	})

	after, err := os.Stat(socket)
	testutil.Check(t, err)

	if !os.SameFile(original, after) {
		t.Fatal("broker socket changed across SSH reconnect")
	}

	for _, name := range []string{"forbidden-mux", "forbidden-hook"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("proof used forbidden multiplexing or hook: %s", name)
		}
	}

	t.Log("real SSH: approved, denied, stable socket handover, old disconnect preserved new route, in-flight loss stayed unknown, native callback cancelled, no master or LocalCommand")
}

func startSSHD(t *testing.T, dir string) string {
	t.Helper()

	for _, name := range []string{"host", "client"} {
		output, err := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput() // #nosec G204 -- Fixed key generator and ephemeral paths owned by this fixture.
		if err != nil {
			t.Fatalf("keys: %s %v", output, err)
		}
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	testutil.Check(t, err)

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("fixture has no TCP address")
	}

	port := address.Port

	cleanup.Close(listener)

	current, err := user.Current()
	testutil.Check(t, err)

	forced := filepath.Join(dir, "forced")
	testutil.Check(t, os.WriteFile(forced, []byte("#!/bin/sh\nexport INTENT_SOCKET_PROOF_HELPER=1\nexec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\"\n"), 0o700)) // #nosec G306 -- The disposable fixture shell must be executable.

	serverConfig := filepath.Join(dir, "sshd_config")
	value := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers %s\nAllowStreamLocalForwarding yes\nForceCommand %s\nLogLevel ERROR\n", port, filepath.Join(dir, "host"), filepath.Join(dir, "pid"), filepath.Join(dir, "client.pub"), current.Username, forced)
	testutil.Check(t, os.WriteFile(serverConfig, []byte(value), 0o600))
	cmd := exec.CommandContext(t.Context(), "/usr/sbin/sshd", "-D", "-e", "-f", serverConfig) // #nosec G204 -- The fixture owns its isolated SSH daemon configuration.
	cmd.Stderr = os.Stderr
	testutil.Check(t, cmd.Start())
	t.Cleanup(func() {
		if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			t.Error(killErr)
		}

		if waitErr := cmd.Wait(); waitErr != nil {
			var exit *exec.ExitError
			if !errors.As(waitErr, &exit) {
				t.Error(waitErr)
			}
		}
	})
	eventually(t, "sshd ready", func() bool {
		conn, dialErr := (&net.Dialer{Timeout: 20 * time.Millisecond}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if dialErr == nil {
			cleanup.Close(conn)
		}

		return dialErr == nil
	})

	config := filepath.Join(dir, "ssh_config")
	value = fmt.Sprintf("Host proof\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityAgent none\n IdentityFile %s\n IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n LogLevel ERROR\n ControlMaster auto\n ControlPersist 30\n ControlPath %s\n PermitLocalCommand yes\n LocalCommand touch %s\n", port, current.Username, filepath.Join(dir, "client"), filepath.Join(dir, "forbidden-mux"), filepath.Join(dir, "forbidden-hook"))
	testutil.Check(t, os.WriteFile(config, []byte(value), 0o600))

	return config
}
