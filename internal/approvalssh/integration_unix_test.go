//go:build !windows

package approvalssh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/intent"
)

// Opt-in: uses a disposable real OpenSSH server and synthetic approval decisions.
// It neither changes SSH configuration nor exercises native authentication.
func TestOpenSSHIntegration(t *testing.T) {
	if os.Getenv("INTENT_SSH_INTEGRATION") != "1" {
		t.Skip("set INTENT_SSH_INTEGRATION=1 for disposable OpenSSH acceptance")
	}
	sshd := "/usr/sbin/sshd"
	if _, err := os.Stat(sshd); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "kl-ssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	binary := filepath.Join(dir, "intent")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/intent")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, name := range []string{"host", "client"} {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput(); err != nil {
			t.Fatalf("keys: %v %s", err, out)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	shell := filepath.Join(dir, "fixture-shell")
	// Leave a background request pending when the shell exits. It ignores HUP
	// and redirects all descriptors, so launcher teardown must cancel its UI.
	fixture := fmt.Sprintf(`#!/bin/sh
printf '%%s' "$INTENT_APPROVAL_SOCKET" > %[1]s/endpoint
%[2]s request --reason 'integration approve' > %[1]s/approved.json
approved=$?
%[2]s request --reason 'integration deny' > %[1]s/denied.json
denied=$?
(trap '' HUP; %[2]s request --reason 'integration pending') < /dev/null > %[1]s/pending.json 2> %[1]s/pending.err &
i=0
while ! test -f %[1]s/pending-ready; do
  i=$((i+1))
  test "$i" -lt 100 || exit 1
  sleep .02
done
test "$approved" = 0 && test "$denied" = 2
`, quote(dir), quote(binary))
	if err = os.WriteFile(shell, []byte(fixture), 0700); err != nil {
		t.Fatal(err)
	}
	forced := filepath.Join(dir, "forced")
	remoteHome := filepath.Join(dir, "remote-home")
	if err = os.Mkdir(remoteHome, 0700); err != nil {
		t.Fatal(err)
	}
	// Delay remote cleanup to expose any service that stays live after shell
	// exit. Correct teardown cancels the pending request before this delay ends.
	forceScript := fmt.Sprintf("#!/bin/sh\nexport PATH=%s:$PATH\nexport SHELL=%s\nexport HOME=%s\nunset INTENT_APPROVAL_SOCKET\nprintf '%%s' \"$SSH_CONNECTION\" > %s\ncase \"$SSH_ORIGINAL_COMMAND\" in *cleanup*) sleep 1; touch %s ;; esac\nexec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\"\n", quote(dir), quote(shell), quote(remoteHome), quote(filepath.Join(dir, "connection")), quote(filepath.Join(dir, "cleanup-finished")))
	if err = os.WriteFile(forced, []byte(forceScript), 0700); err != nil {
		t.Fatal(err)
	}
	serverConfig := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers %s\nAllowStreamLocalForwarding yes\nForceCommand %s\nLogLevel ERROR\n", port, filepath.Join(dir, "host"), filepath.Join(dir, "pid"), filepath.Join(dir, "client.pub"), current.Username, forced)
	config := filepath.Join(dir, "sshd_config")
	if err = os.WriteFile(config, []byte(serverConfig), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "sshd.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	serverCtx, stopServer := context.WithCancel(context.Background())
	server := exec.CommandContext(serverCtx, sshd, "-D", "-e", "-f", config)
	server.Stdout, server.Stderr = log, log
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()
	defer func() { stopServer(); <-serverDone }()
	clientConfig := fmt.Sprintf("Host fixture\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n LogLevel ERROR\n", port, current.Username, filepath.Join(dir, "client"))
	sshConfig := filepath.Join(dir, "ssh_config")
	if err = os.WriteFile(sshConfig, []byte(clientConfig), 0600); err != nil {
		t.Fatal(err)
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(dir, "local-bin")
	if err = os.Mkdir(wrapperDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrapper := fmt.Sprintf("#!/bin/sh\nexec %s -F %s \"$@\"\n", quote(sshPath), quote(sshConfig))
	if err = os.WriteFile(filepath.Join(wrapperDir, "ssh"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ready := false
	for range 100 {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 20*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case err := <-serverDone:
			serverDone <- err
			data, _ := os.ReadFile(logPath)
			t.Fatalf("sshd stopped: %v\n%s", err, data)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(logPath)
		t.Fatalf("sshd not ready\n%s", data)
	}
	var mu sync.Mutex
	var prompts []intent.Prompt
	cancelled := make(chan struct{}, 2)
	authenticate := func(ctx context.Context, p intent.Prompt) approval.Decision {
		mu.Lock()
		prompts = append(prompts, p)
		mu.Unlock()
		if strings.HasSuffix(p.Reason, "pending") {
			_ = os.WriteFile(filepath.Join(dir, "pending-ready"), []byte("ready"), 0600)
			<-ctx.Done()
			cancelled <- struct{}{}
			return approval.Approved // A late success must never be delivered.
		}
		if strings.HasSuffix(p.Reason, "deny") {
			return approval.Denied
		}
		return approval.Approved
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 2 {
		_ = os.Remove(filepath.Join(dir, "pending-ready"))
		_ = os.Remove(filepath.Join(dir, "cleanup-finished"))
		done := make(chan error, 1)
		finished := make(chan struct{})
		go func() { defer close(finished); done <- launch(ctx, "fixture", authenticate) }()
		// Even an assertion failure must join launcher teardown before removing
		// its disposable SSH configuration and stopping the test server.
		defer func() { cancel(); <-finished }()
		select {
		case <-cancelled:
			// Cleanup deliberately takes a second. Cancellation should precede it.
			if _, err := os.Stat(filepath.Join(dir, "cleanup-finished")); !os.IsNotExist(err) {
				t.Fatalf("pending UI survived until remote cleanup finished: %v", err)
			}
			select {
			case err := <-done:
				t.Fatalf("launcher ended before pending cancellation was observed: %v", err)
			default:
			}
		case <-ctx.Done():
			t.Fatal("pending request survived shell exit")
		}
		if err = <-done; err != nil {
			data, _ := os.ReadFile(logPath)
			t.Fatalf("launcher: %v\n%s", err, data)
		}
		if _, err := os.Stat(filepath.Join(dir, "cleanup-finished")); err != nil {
			t.Fatalf("remote cleanup did not run: %v", err)
		}
	}
	for name, want := range map[string]approval.Decision{"approved": approval.Approved, "denied": approval.Denied} {
		data, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var result approval.Result
		if err = json.Unmarshal(data, &result); err != nil || result.Decision != want {
			t.Fatalf("%s: %s %v", name, data, err)
		}
	}
	endpoint, err := os.ReadFile(filepath.Join(dir, "endpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Dir(string(endpoint))); !os.IsNotExist(err) {
		t.Fatalf("remote directory retained: %s %v", endpoint, err)
	}
	mu.Lock()
	if len(prompts) != 6 || prompts[0].Host != "fixture" || prompts[0].Session == "" || prompts[0].Session != prompts[1].Session || prompts[0].ID == prompts[1].ID || prompts[0].Session == prompts[3].Session {
		t.Fatalf("wrong session/request binding: %+v", prompts)
	}
	mu.Unlock()
	if runtime.GOOS == "darwin" {
		testSSHConfigHook(t, dir, binary, sshConfig, remoteHome)
	}
}

// Exercise ordinary ssh, its real LocalCommand and the detached broker. Only
// the native authentication callback is synthetic; no human authentication is claimed.
func testSSHConfigHook(t *testing.T, dir, binary, sshConfig, remoteHome string) {
	t.Helper()
	localHome := filepath.Join(dir, "local-home")
	controlDir := filepath.Join(localHome, "control")
	if err := os.MkdirAll(controlDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", localHome)
	t.Setenv("INTENT_HOOK_FAKE_NATIVE", "1")
	promptLog := filepath.Join(dir, "hook-prompts.jsonl")
	t.Setenv("INTENT_HOOK_PROMPT_LOG", promptLog)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(controlDir, "master")
	f, err := os.OpenFile(sshConfig, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(f, "\nHost fixture\n ControlMaster auto\n ControlPersist 3\n ControlPath %s\n PermitLocalCommand yes\n LocalCommand %s ssh-hook --control %s\n", control, quote(exe), quote(control))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exec.Command("ssh", "-S", control, "-O", "exit", "fixture").Run() }()
	for _, test := range []struct {
		reason   string
		decision approval.Decision
		code     int
	}{
		{"config approve", approval.Approved, 0}, {"config deny", approval.Denied, 2},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, "ssh", "fixture", "intent request --reason "+quote(test.reason))
		output, err := cmd.Output()
		cancel()
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
				t.Logf("SSH stderr: %s", e.Stderr)
			} else {
				t.Fatal(err)
			}
		}
		var result approval.Result
		if code != test.code || json.Unmarshal(output, &result) != nil || result.Decision != test.decision {
			logs, _ := filepath.Glob(filepath.Join(localHome, ".intent-ssh", "*.log"))
			for _, path := range logs {
				data, _ := os.ReadFile(path)
				t.Logf("hook log: %s", data)
			}
			t.Fatalf("ordinary ssh: code %d, output %s, error %v", code, output, err)
		}
	}
	data, err := os.ReadFile(promptLog)
	if err != nil {
		t.Fatal(err)
	}
	var seen []intent.Prompt
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var p intent.Prompt
		if err = json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, p)
	}
	if len(seen) != 2 || seen[0].Session != seen[1].Session || !strings.Contains(seen[0].Host, "127.0.0.1") {
		t.Fatalf("unbound/shared metadata: %+v", seen)
	}
	// Simultaneous hooks on an existing connection must not replace its service.
	errors := make(chan error, 2)
	for range 2 {
		go func() { errors <- exec.Command(exe, "ssh-hook", "--control", control).Run() }()
	}
	for range 2 {
		if err = <-errors; err != nil {
			t.Fatal(err)
		}
	}
	oldReceipts, _ := filepath.Glob(filepath.Join(remoteHome, ".intent-approval", "*.json"))
	var oldSockets []string
	for _, path := range oldReceipts {
		data, _ := os.ReadFile(path)
		var r struct{ Socket string }
		if json.Unmarshal(data, &r) == nil {
			oldSockets = append(oldSockets, r.Socket)
		}
	}
	ready, err := hookPath(control, "ready")
	if err != nil {
		t.Fatal(err)
	}
	waitIdle := func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			_, controlErr := os.Stat(control)
			_, readyErr := os.Stat(ready)
			if os.IsNotExist(controlErr) && os.IsNotExist(readyErr) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("broker monitoring sustained the idle SSH master")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// Do not send -O exit or poll the mux: its own three-second idle timeout must
	// expire naturally, and its broker must stop without sustaining that timer.
	waitIdle()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	output, err := exec.CommandContext(ctx, "ssh", "fixture", "intent request --reason 'config approve after reconnect'").CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("reconnect: %v %s", err, output)
	}
	for _, path := range oldReceipts {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("stale receipt survived reconnect", path, err)
		}
	}
	for _, socket := range oldSockets {
		if _, err = os.Stat(filepath.Dir(socket)); !os.IsNotExist(err) {
			t.Fatal("stale endpoint survived reconnect", socket, err)
		}
	}
	waitIdle()
	// A final disconnected fixture has no next setup to trigger recovery. Remove
	// its known synthetic artifacts after testing the real reconnect recovery.
	receipts, _ := filepath.Glob(filepath.Join(remoteHome, ".intent-approval", "*.json"))
	for _, path := range receipts {
		data, _ := os.ReadFile(path)
		var r struct{ Socket string }
		if json.Unmarshal(data, &r) == nil && validRemoteSocket(r.Socket) {
			_ = os.RemoveAll(filepath.Dir(r.Socket))
		}
	}
}
