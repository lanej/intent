//go:build !windows

package approvalssh

import (
	"context"
	"encoding/json"
	"errors"
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

	"github.com/lanej/intent/internal/testutil"

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

	dir, err := os.MkdirTemp("/tmp", "kl-ssh-test-") //nolint:usetesting // Unix socket fixtures require short paths on macOS.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { testutil.Check(t, os.RemoveAll(dir)) }()

	binary := filepath.Join(dir, "intent")

	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "../../cmd/intent") // #nosec G204 -- Disposable test commands use controlled executable paths and argument vectors.
	if out, combinedOutputErr := build.CombinedOutput(); combinedOutputErr != nil {
		t.Fatalf("build: %v\n%s", combinedOutputErr, out)
	}

	for _, name := range []string{"host", "client"} {
		if out, combinedOutputErr := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput(); combinedOutputErr != nil { // #nosec G204 -- Disposable test commands use controlled executable paths and argument vectors.
			t.Fatalf("keys: %v %s", combinedOutputErr, out)
		}
	}

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("fixture listener has no TCP address")
	}

	port := address.Port

	testutil.Close(t, l)

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
	if err = os.WriteFile(shell, []byte(fixture), 0o700); err != nil { // #nosec G306 -- The fixture intentionally needs executable or insecure permissions to exercise this boundary.
		t.Fatal(err)
	}

	forced := filepath.Join(dir, "forced")

	remoteHome := filepath.Join(dir, "remote-home")
	if err = os.Mkdir(remoteHome, 0o700); err != nil {
		t.Fatal(err)
	}
	// Delay remote cleanup to expose any service that stays live after shell
	// exit. Correct teardown cancels the pending request before this delay ends.
	forceScript := fmt.Sprintf("#!/bin/sh\nexport PATH=%s:$PATH\nexport SHELL=%s\nexport HOME=%s\nunset INTENT_APPROVAL_SOCKET\nprintf '%%s' \"$SSH_CONNECTION\" > %s\ncase \"$SSH_ORIGINAL_COMMAND\" in *cleanup*) sleep 1; touch %s ;; esac\nexec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\"\n", quote(dir), quote(shell), quote(remoteHome), quote(filepath.Join(dir, "connection")), quote(filepath.Join(dir, "cleanup-finished")))
	if err = os.WriteFile(forced, []byte(forceScript), 0o700); err != nil { // #nosec G306 -- The fixture intentionally needs executable or insecure permissions to exercise this boundary.
		t.Fatal(err)
	}

	serverConfig := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers %s\nAllowStreamLocalForwarding yes\nForceCommand %s\nLogLevel ERROR\n", port, filepath.Join(dir, "host"), filepath.Join(dir, "pid"), filepath.Join(dir, "client.pub"), current.Username, forced)

	config := filepath.Join(dir, "sshd_config")
	if err = os.WriteFile(config, []byte(serverConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, "sshd.log")

	log, err := os.Create(logPath) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.Close(t, log)

	serverCtx, stopServer := context.WithCancel(context.Background())
	server := exec.CommandContext(serverCtx, sshd, "-D", "-e", "-f", config) // #nosec G204 -- Disposable test commands use controlled executable paths and argument vectors.

	server.Stdout, server.Stderr = log, log
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()

	defer func() { stopServer(); <-serverDone }()

	occupiedForward, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.Close(t, occupiedForward)

	forwardAddress, ok := occupiedForward.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("fixture forward listener has no TCP address")
	}

	unrequestedSocket := filepath.Join(dir, "unrequested.sock")

	clientConfig := fmt.Sprintf("Host fixture\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n LogLevel ERROR\n", port, current.Username, filepath.Join(dir, "client"))

	// Configured application forwards must not be recreated by approval setup.
	clientConfig += fmt.Sprintf(" LocalForward 127.0.0.1:%d 127.0.0.1:9\n RemoteForward %s 127.0.0.1:9\n", forwardAddress.Port, unrequestedSocket)

	sshConfig := filepath.Join(dir, "ssh_config")
	if err = os.WriteFile(sshConfig, []byte(clientConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}

	wrapperDir := filepath.Join(dir, "local-bin")
	if err = os.Mkdir(wrapperDir, 0o700); err != nil {
		t.Fatal(err)
	}

	wrapper := fmt.Sprintf("#!/bin/sh\nexec %s -F %s \"$@\"\n", quote(sshPath), quote(sshConfig))
	if err = os.WriteFile(filepath.Join(wrapperDir, "ssh"), []byte(wrapper), 0o700); err != nil { // #nosec G306 -- The fixture intentionally needs executable or insecure permissions to exercise this boundary.
		t.Fatal(err)
	}

	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ready := false

	for range 100 {
		conn, dialTimeoutErr := (&net.Dialer{Timeout: 20 * time.Millisecond}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if dialTimeoutErr == nil {
			testutil.Close(t, conn)

			ready = true

			break
		}

		select {
		case serverErr := <-serverDone:
			serverDone <- serverErr

			data, checkedErr5 := os.ReadFile(logPath) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
			testutil.Check(t, checkedErr5)
			t.Fatalf("sshd stopped: %v\n%s", serverErr, data)
		default:
		}

		time.Sleep(20 * time.Millisecond)
	}

	if !ready {
		data, checkedErr6 := os.ReadFile(logPath) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
		testutil.Check(t, checkedErr6)
		t.Fatalf("sshd not ready\n%s", data)
	}

	var (
		mu      sync.Mutex
		prompts []intent.Prompt
	)

	cancelled := make(chan struct{}, 2)
	authenticate := func(ctx context.Context, p intent.Prompt) approval.Decision {
		mu.Lock()

		prompts = append(prompts, p)
		mu.Unlock()

		if strings.HasSuffix(p.Reason, "pending") {
			testutil.Check(t, os.WriteFile(filepath.Join(dir, "pending-ready"), []byte("ready"), 0o600))

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
		if removeErr := os.Remove(filepath.Join(dir, "pending-ready")); removeErr != nil && !os.IsNotExist(removeErr) {
			t.Error(removeErr)
		}

		if removeErr := os.Remove(filepath.Join(dir, "cleanup-finished")); removeErr != nil && !os.IsNotExist(removeErr) {
			t.Error(removeErr)
		}

		done := make(chan error, 1)

		finished := make(chan struct{})
		go func() { defer close(finished); done <- launch(ctx, "fixture", authenticate) }()
		// Even an assertion failure must join launcher teardown before removing
		// its disposable SSH configuration and stopping the test server.
		defer func() { cancel(); <-finished }()

		select {
		case <-cancelled:
			if _, statErr := os.Lstat(unrequestedSocket); !os.IsNotExist(statErr) {
				t.Fatalf("approval setup activated an unrelated configured forward: %v", statErr)
			}

			// Cleanup deliberately takes a second. Cancellation should precede it.
			if _, statErr := os.Stat(filepath.Join(dir, "cleanup-finished")); !os.IsNotExist(statErr) {
				t.Fatalf("pending UI survived until remote cleanup finished: %v", statErr)
			}

			select {
			case localErr := <-done:
				t.Fatalf("launcher ended before pending cancellation was observed: %v", localErr)
			default:
			}
		case launchErr := <-done:
			t.Fatalf("launcher stopped before approval: %v", launchErr)
		case <-ctx.Done():
			t.Fatal("pending request survived shell exit")
		}

		if err = <-done; err != nil {
			data, checkedErr10 := os.ReadFile(logPath) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
			testutil.Check(t, checkedErr10)
			t.Fatalf("launcher: %v\n%s", err, data)
		}

		if _, statErr := os.Stat(filepath.Join(dir, "cleanup-finished")); statErr != nil {
			t.Fatalf("remote cleanup did not run: %v", statErr)
		}
	}

	for name, want := range map[string]approval.Decision{"approved": approval.Approved, "denied": approval.Denied} {
		data, readFileErr := os.ReadFile(filepath.Join(dir, name+".json")) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
		if readFileErr != nil {
			t.Fatal(readFileErr)
		}

		var result approval.Result
		if readFileErr = json.Unmarshal(data, &result); readFileErr != nil || result.Decision != want {
			t.Fatalf("%s: %s %v", name, data, readFileErr)
		}
	}

	endpoint, err := os.ReadFile(filepath.Join(dir, "endpoint")) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
	if err != nil {
		t.Fatal(err)
	}

	if _, err = os.Stat(filepath.Dir(string(endpoint))); !os.IsNotExist(err) { // #nosec G703 -- This path belongs to the controlled disposable test fixture.
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
	if err := os.MkdirAll(controlDir, 0o700); err != nil {
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

	f, err := os.OpenFile(sshConfig, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
	if err != nil {
		t.Fatal(err)
	}

	_, err = fmt.Fprintf(f, "\nHost fixture\n ControlMaster auto\n ControlPersist 3\n ControlPath %s\n PermitLocalCommand yes\n LocalCommand %s ssh-hook --control %s\n", control, quote(exe), quote(control))
	testutil.Close(t, f)

	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()

		exitErr := exec.CommandContext(cleanupCtx, "ssh", "-S", control, "-O", "exit", "fixture").Run() // #nosec G204 -- The fixture owns this private mux path and passes a fixed exit operation as argv.
		if exitErr != nil {
			if _, statErr := os.Lstat(control); !os.IsNotExist(statErr) {
				t.Errorf("owned SSH master cleanup failed: %v", exitErr)
			}
		}
	}()

	for _, test := range []struct {
		reason   string
		decision approval.Decision
		code     int
	}{
		{"config approve", approval.Approved, 0}, {"config deny", approval.Denied, 2},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, "ssh", "fixture", "intent request --reason "+quote(test.reason)) // #nosec G204 -- Disposable test commands use controlled executable paths and argument vectors.
		output, outputErr := cmd.Output()

		cancel()

		code := 0

		if outputErr != nil {
			var e *exec.ExitError
			if errors.As(outputErr, &e) {
				code = e.ExitCode()
				t.Logf("SSH stderr: %s", e.Stderr)
			} else {
				t.Fatal(outputErr)
			}
		}

		var result approval.Result
		if code != test.code || json.Unmarshal(output, &result) != nil || result.Decision != test.decision {
			logs, checkedErr13 := filepath.Glob(filepath.Join(localHome, ".intent-ssh", "*.log"))
			testutil.Check(t, checkedErr13)

			for _, path := range logs {
				data, checkedErr14 := os.ReadFile(path) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
				testutil.Check(t, checkedErr14)
				t.Logf("hook log: %s", data)
			}

			t.Fatalf("ordinary ssh: code %d, output %s, error %v", code, output, outputErr)
		}
	}

	data, err := os.ReadFile(promptLog) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
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
	hookErrors := make(chan error, 2)

	for range 2 {
		go func() { hookErrors <- exec.CommandContext(t.Context(), exe, "ssh-hook", "--control", control).Run() }() // #nosec G204 -- Disposable test commands use controlled executable paths and argument vectors.
	}

	for range 2 {
		if err = <-hookErrors; err != nil {
			t.Fatal(err)
		}
	}

	oldReceipts, checkedErr15 := filepath.Glob(filepath.Join(remoteHome, ".intent-approval", "*.json"))
	testutil.Check(t, checkedErr15)

	var oldSockets []string

	for _, path := range oldReceipts {
		data, checkedErr16 := os.ReadFile(path) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
		testutil.Check(t, checkedErr16)

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
	receipts, checkedErr17 := filepath.Glob(filepath.Join(remoteHome, ".intent-approval", "*.json"))
	testutil.Check(t, checkedErr17)

	for _, path := range receipts {
		data, checkedErr18 := os.ReadFile(path) // #nosec G304 -- This path belongs to the controlled disposable test fixture.
		testutil.Check(t, checkedErr18)

		var r struct{ Socket string }
		if json.Unmarshal(data, &r) == nil && validRemoteSocket(r.Socket) {
			testutil.Check(t, os.RemoveAll(filepath.Dir(r.Socket)))
		}
	}
}
