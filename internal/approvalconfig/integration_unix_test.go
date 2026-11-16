//go:build !windows

package approvalconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalforward"
	"github.com/lanej/intent/internal/intent"
	"github.com/lanej/intent/internal/testutil"
)

// This disposable sshd checks normal OpenSSH transports and actual forwarding,
// with synthetic authentication. It never touches the user's SSH configuration.
func TestOrdinaryOpenSSHIntegration(t *testing.T) {
	if os.Getenv("INTENT_SSH_INTEGRATION") != "1" {
		t.Skip("set INTENT_SSH_INTEGRATION=1 for disposable OpenSSH acceptance")
	}

	dir, err := os.MkdirTemp("/tmp", "oi-") //nolint:usetesting // Keep all real socket paths within macOS's pathname limit.

	testutil.Check(t, err)
	defer func() { testutil.Check(t, os.RemoveAll(dir)) }()

	binary := filepath.Join(dir, "intent")
	if out, buildErr := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "../../cmd/intent").CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v %s", buildErr, out)
	} // #nosec G204 -- Controlled disposable fixture builds the repository CLI.

	for _, name := range []string{"host", "client"} {
		if out, keyErr := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput(); keyErr != nil {
			t.Fatalf("key: %v %s", keyErr, out)
		}
	} // #nosec G204 -- Controlled fixture generates disposable keys.

	t.Setenv("HOME", dir)
	remote := filepath.Join(dir, "remote")
	testutil.Check(t, os.Mkdir(remote, 0o700))
	testutil.Check(t, Configure(t.Context(), "fixture", remote, binary))

	sum := sha256.Sum256([]byte("fixture"))
	profile := filepath.Join(dir, ".intent-ssh", hex.EncodeToString(sum[:16]), "profile.json")
	p, err := readProfile(profile)
	testutil.Check(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serviceDone := make(chan error, 1)

	var calls atomic.Int32

	pendingStarted := make(chan struct{}, 1)
	pendingCancelled := make(chan struct{}, 1)

	auth := func(requestCtx context.Context, prompt intent.Prompt) approval.Decision {
		calls.Add(1)

		if !prompt.Shared {
			t.Error("persistent service incorrectly labelled SSH session")
		}

		if prompt.Reason == "pending" {
			pendingStarted <- struct{}{}

			<-requestCtx.Done()

			pendingCancelled <- struct{}{}

			return approval.Approved
		}

		if prompt.Reason == "deny" {
			return approval.Denied
		}

		return approval.Approved
	}
	go func() { serviceDone <- serve(ctx, profile, auth) }()

	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- approval.ServeRemoteBroker(ctx, approval.RemoteBrokerConfig{Directory: remote, MacID: p.MacID})
	}()

	defer func() { cancel(); testutil.Check(t, <-serviceDone); testutil.Check(t, <-brokerDone) }()

	tcp, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	testutil.Check(t, err)

	addr, ok := tcp.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("no TCP address")
	}

	port := addr.Port

	testutil.Close(t, tcp)

	current, err := user.Current()
	testutil.Check(t, err)

	forced := filepath.Join(dir, "forced")
	forceScript := fmt.Sprintf("#!/bin/sh\nexport INTENT_APPROVAL_SOCKET=%s\nexec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\"\n", quote(filepath.Join(remote, "approval.sock")))
	testutil.Check(t, os.WriteFile(forced, []byte(forceScript), 0o700)) // #nosec G306 -- Fixture shell must be executable.

	serverConfig := filepath.Join(dir, "sshd_config")
	body := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers %s\nAllowStreamLocalForwarding yes\nForceCommand %s\nLogLevel ERROR\n", port, filepath.Join(dir, "host"), filepath.Join(dir, "pid"), filepath.Join(dir, "client.pub"), current.Username, forced)
	testutil.Check(t, os.WriteFile(serverConfig, []byte(body), 0o600))

	serverLog, err := os.Create(filepath.Join(dir, "sshd.log")) // #nosec G304 -- Private disposable fixture log.

	testutil.Check(t, err)
	defer testutil.Close(t, serverLog)

	serverCtx, stopServer := context.WithCancel(t.Context())
	server := exec.CommandContext(serverCtx, "/usr/sbin/sshd", "-D", "-e", "-f", serverConfig) // #nosec G204 -- Explicit disposable sshd with temporary keys and configuration.
	server.Stdout, server.Stderr = serverLog, serverLog
	testutil.Check(t, server.Start())

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()

	defer func() { stopServer(); <-serverDone }()

	readyCtx, stopReady := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopReady()

	for {
		conn, dialErr := (&net.Dialer{}).DialContext(readyCtx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if dialErr == nil {
			testutil.Close(t, conn)
			break
		}

		select {
		case <-readyCtx.Done():
			t.Fatal("sshd did not start", dialErr)
		case <-time.After(10 * time.Millisecond):
		}
	}

	clientConfig := filepath.Join(dir, "ssh_config")
	clientBody := fmt.Sprintf("Include %s\nHost fixture\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n LogLevel ERROR\n", configQuote(filepath.Join(filepath.Dir(profile), "ssh.conf")), port, current.Username, filepath.Join(dir, "client"))
	// An application forward must remain usable during the approval connection.
	application := filepath.Join(dir, "application.sock")
	appListener, listenErr := (&net.ListenConfig{}).Listen(ctx, "unix", application)

	testutil.Check(t, listenErr)
	defer testutil.Close(t, appListener)

	appDone := make(chan struct{})
	go func() {
		defer close(appDone)

		for {
			conn, acceptErr := appListener.Accept()
			if acceptErr != nil {
				return
			}

			go func() {
				defer testutil.Close(t, conn)

				var data [1]byte
				if _, copyErr := io.ReadFull(conn, data[:]); copyErr != nil {
					return
				}

				if _, writeErr := conn.Write(data[:]); writeErr != nil {
					return
				}
			}()
		}
	}()

	defer func() { testutil.Close(t, appListener); <-appDone }()

	appLocal := filepath.Join(dir, "app-local.sock")
	appRemote := filepath.Join(dir, "app.sock")
	clientBody += " RemoteForward " + appRemote + " " + application + "\n LocalForward " + appLocal + " " + application + "\n"
	testutil.Check(t, os.WriteFile(clientConfig, []byte(clientBody), 0o600))

	startSSH := func(command string) (context.CancelFunc, <-chan error) {
		childCtx, stop := context.WithCancel(t.Context())
		child := exec.CommandContext(childCtx, "ssh", "-F", clientConfig, "-T", "fixture", command) // #nosec G204 -- Ordinary SSH connects only to the disposable test server.
		log, logErr := os.CreateTemp(dir, "ssh-")
		testutil.Check(t, logErr)

		child.Stdout, child.Stderr = log, log
		testutil.Check(t, child.Start())

		done := make(chan error, 1)
		go func() { done <- child.Wait(); testutil.Close(t, log) }()

		return stop, done
	}

	stopFirst, firstDone := startSSH("sleep 20")

	firstStopped := false
	defer func() {
		if !firstStopped {
			stopFirst()
			<-firstDone
		}
	}()

	matching := func() []string {
		paths, globErr := filepath.Glob(filepath.Join(remote, p.MacID+"-*.sock"))
		testutil.Check(t, globErr)

		return paths
	}
	client := approval.NewClient(filepath.Join(remote, "approval.sock"))
	ready := func(reason string) approval.Result {
		deadline := time.Now().Add(4 * time.Second)

		for {
			result, requestErr := client.Approve(t.Context(), approval.Request{Reason: reason})
			if requestErr == nil && result.Decision != approval.Unavailable {
				return result
			}

			if time.Now().After(deadline) {
				t.Fatal("ordinary forward unavailable", reason, matching(), result, requestErr)
			}

			time.Sleep(10 * time.Millisecond)
		}
	}

	if result := ready("approve"); result.Decision != approval.Approved {
		t.Fatal(result)
	}

	for _, socket := range []string{appLocal, appRemote} {
		connection, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "unix", socket)
		if dialErr != nil {
			t.Fatal("configured application forward missing", socket, dialErr)
		}

		testutil.Check(t, connection.SetDeadline(time.Now().Add(time.Second)))

		if _, writeErr := connection.Write([]byte("x")); writeErr != nil {
			t.Fatal(writeErr)
		}

		var payload [1]byte
		if _, readErr := io.ReadFull(connection, payload[:]); readErr != nil || payload[0] != 'x' {
			t.Fatal("application forward not functional", socket, readErr)
		}

		testutil.Close(t, connection)
	}

	if result := ready("deny"); result.Decision != approval.Denied {
		t.Fatal(result)
	}

	initial := matching()
	if len(initial) != 1 {
		t.Fatal("expected exactly one initial transport", initial)
	}

	firstTransport := initial[0]
	pendingCtx, stopPending := context.WithCancel(t.Context())
	pendingDone := make(chan error, 1)

	go func() {
		_, requestErr := client.Approve(pendingCtx, approval.Request{Reason: "pending"})
		pendingDone <- requestErr
	}()

	select {
	case <-pendingStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("native pending request missing")
	}

	stopSecond, secondDone := startSSH("sleep 20")

	secondStopped := false
	defer func() {
		if !secondStopped {
			stopSecond()
			<-secondDone
		}
	}()

	handoverDeadline := time.Now().Add(3 * time.Second)

	var secondTransport string

	for {
		for _, path := range matching() {
			if path != firstTransport && approvalforward.Probe(t.Context(), path, p.MacID) == nil {
				secondTransport = path
			}
		}

		if secondTransport != "" {
			break
		}

		if time.Now().After(handoverDeadline) {
			t.Fatal("second SSH connection has no usable transport")
		}

		time.Sleep(10 * time.Millisecond)
	}
	// Removing this fixture-owned pathname keeps its established pending channel
	// alive but makes new calls use the second transport exclusively.
	testutil.Check(t, os.Remove(firstTransport))

	if result := ready("shared service busy"); result.Decision != approval.Busy {
		t.Fatal("parallel transports must share the same service's busy policy", result)
	}

	stopPending()

	if err = <-pendingDone; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	select {
	case <-pendingCancelled:
	case <-time.After(time.Second):
		t.Fatal("SSH channel EOF did not cancel authentication")
	}

	if result := ready("after cancellation"); result.Decision != approval.Approved {
		t.Fatal(result)
	}
	// Background (-f) SSH forks after LocalCommand. Parsed routes remain usable
	// even though its pre-fork parser metadata may be pruned by the next parse.
	stopFirst()
	<-firstDone

	firstStopped = true

	stopSecond()
	<-secondDone

	secondStopped = true

	forkLog, logErr := os.Create(filepath.Join(dir, "background.log")) // #nosec G304 -- Disposable background-SSH fixture log.

	testutil.Check(t, logErr)
	defer testutil.Close(t, forkLog)

	fork := exec.CommandContext(t.Context(), "ssh", "-F", clientConfig, "-f", "-T", "fixture", "sleep 2") // #nosec G204 -- Controlled disposable connection exercises real OpenSSH forking.
	// A pipe-backed CombinedOutput waits for the forked child's inherited output
	// to close, which would test the route only after that child has exited.
	fork.Stdout, fork.Stderr = forkLog, forkLog
	if forkErr := fork.Run(); forkErr != nil {
		t.Fatal("background SSH", forkErr)
	}

	if result := ready("background connection"); result.Decision != approval.Approved {
		t.Fatal(result)
	}
	// Wait for this task-owned background transport to end before fixture cleanup.
	time.Sleep(2200 * time.Millisecond)

	if calls.Load() != 5 {
		t.Fatal("readiness probes entered authentication or requests replayed", calls.Load())
	}
}
