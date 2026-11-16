//go:build !windows

package approvalforward_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalforward"
	"github.com/lanej/intent/internal/intent"
	"github.com/lanej/intent/internal/testutil"
)

const pairedMac = "11111111111111111111111111111111"

func shortDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "it-") //nolint:usetesting // Pathname socket fixtures must fit macOS's sun_path.
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { testutil.Check(t, os.RemoveAll(dir)) })

	return dir
}

func waitSocket(t *testing.T, path string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err == nil {
			testutil.Close(t, conn)
			return
		}

		select {
		case <-ctx.Done():
			t.Fatal("socket not ready", path, err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func transport(t *testing.T, dir, mac, session string, auth intent.Authenticate) (string, context.CancelFunc) {
	t.Helper()

	path := filepath.Join(dir, mac+"-"+session+".sock")
	ctx, cancel := context.WithCancel(t.Context())

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		t.Fatal(err)
	}

	service := &intent.Service{Host: "fixture", Session: session, Shared: true, Authenticate: auth}

	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, listener) }()

	t.Cleanup(func() { cancel(); testutil.Check(t, <-done) })

	return path, cancel
}

func broker(t *testing.T, dir string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- approval.ServeRemoteBroker(ctx, approval.RemoteBrokerConfig{Directory: dir, MacID: pairedMac})
	}()

	waitSocket(t, filepath.Join(dir, "approval.sock"))

	stopped := make(chan struct{})
	stop := func() {
		cancel()

		select {
		case <-stopped:
			return
		default:
		}

		testutil.Check(t, <-done)
		close(stopped)
	}
	t.Cleanup(stop)

	return stop
}

func TestStableBrokerHandoverAndNoReplay(t *testing.T) {
	dir := shortDir(t)
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)

	var calls atomic.Int32

	older, stopOlder := transport(t, dir, pairedMac, strings.Repeat("2", 32), func(ctx context.Context, p intent.Prompt) approval.Decision {
		calls.Add(1)

		if p.Reason == "pending" {
			started <- struct{}{}

			<-ctx.Done()

			cancelled <- struct{}{}

			return approval.Approved
		}

		return approval.Denied
	})
	testutil.Check(t, os.Chtimes(older, time.Unix(10, 0), time.Unix(10, 0)))
	stopBroker := broker(t, dir)
	socket := filepath.Join(dir, "approval.sock")
	before, err := os.Stat(socket)
	testutil.Check(t, err)

	client := approval.NewClient(socket)

	result, err := client.Approve(t.Context(), approval.Request{Reason: "old route"})
	if err != nil || result.Decision != approval.Denied {
		t.Fatal(result, err)
	}

	pending := make(chan error, 1)

	go func() {
		_, requestErr := client.Approve(t.Context(), approval.Request{Reason: "pending"})
		pending <- requestErr
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("pending native request not started")
	}

	var newerCalls atomic.Int32

	newer, stopNewer := transport(t, dir, pairedMac, strings.Repeat("3", 32), func(context.Context, intent.Prompt) approval.Decision { newerCalls.Add(1); return approval.Approved })
	testutil.Check(t, os.Chtimes(newer, time.Unix(20, 0), time.Unix(20, 0)))
	other, _ := transport(t, dir, strings.Repeat("9", 32), strings.Repeat("8", 32), func(context.Context, intent.Prompt) approval.Decision {
		t.Error("another Mac selected")
		return approval.Approved
	})
	testutil.Check(t, os.Chtimes(other, time.Unix(30, 0), time.Unix(30, 0)))

	result, err = client.Approve(t.Context(), approval.Request{Reason: "new route"})
	if err != nil || result.Decision != approval.Approved {
		t.Fatal(result, err)
	}

	after, err := os.Stat(socket)
	testutil.Check(t, err)

	if !os.SameFile(before, after) {
		t.Fatal("stable socket replaced during handover")
	}

	stopOlder()

	select {
	case err = <-pending:
		if !errors.Is(err, approval.ErrOutcomeUnknown) {
			t.Fatal("submitted call must preserve uncertainty", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old call did not close")
	}

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("native request not cancelled on transport loss")
	}

	if newerCalls.Load() != 1 || calls.Load() != 2 {
		t.Fatal("submitted approval replayed", calls.Load(), newerCalls.Load())
	}

	stopBroker()
	// A client keeps the stable path across broker restarts and newly created transports.
	broker(t, dir)

	result, err = client.Approve(t.Context(), approval.Request{Reason: "broker restarted"})
	if err != nil || result.Decision != approval.Approved {
		t.Fatal(result, err)
	}

	stopNewer()

	result, err = client.Approve(t.Context(), approval.Request{Reason: "no paired route"})
	if err != nil || result.Decision != approval.Unavailable {
		t.Fatal(result, err)
	}
}

func TestProbeCannotAuthenticateAndCallerCancellation(t *testing.T) {
	dir := shortDir(t)
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)

	var calls atomic.Int32

	path, _ := transport(t, dir, pairedMac, strings.Repeat("4", 32), func(ctx context.Context, _ intent.Prompt) approval.Decision {
		calls.Add(1)

		started <- struct{}{}

		<-ctx.Done()

		cancelled <- struct{}{}

		return approval.Approved
	})
	testutil.Check(t, approvalforward.Probe(t.Context(), path, pairedMac))

	if calls.Load() != 0 {
		t.Fatal("readiness probe entered authentication")
	}

	broker(t, dir)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() {
		_, err := approval.NewClient(filepath.Join(dir, "approval.sock")).Approve(ctx, approval.Request{Reason: "cancel me"})
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("native request not started")
	}

	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("caller EOF did not cancel authentication")
	}
}

func TestUnexpectedEndpointsArePreserved(t *testing.T) {
	dir := shortDir(t)
	lock, err := approvalforward.Lock(dir, "broker.lock")

	testutil.Check(t, err)
	defer testutil.Close(t, lock)

	path := filepath.Join(dir, "approval.sock")
	testutil.Check(t, os.WriteFile(path, []byte("valuable"), 0o600))

	if _, err = approvalforward.Listen(t.Context(), path); err == nil {
		t.Fatal("unexpected endpoint accepted")
	}

	data, err := os.ReadFile(path) // #nosec G304 -- The path belongs to the owned disposable endpoint fixture.
	testutil.Check(t, err)

	if string(data) != "valuable" {
		t.Fatal("file overwritten")
	}

	if err = approvalforward.SocketPath("/" + strings.Repeat("a", 103)); err == nil {
		t.Fatal("oversized socket accepted")
	}
}

func TestIndependentSweepRecoversBeyondRoutingCap(t *testing.T) {
	dir := shortDir(t)

	for i := range 2050 {
		name := fmt.Sprintf("%032x", i+100)
		socket := filepath.Join(dir, pairedMac+"-"+name+".sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		testutil.Check(t, err)
		listener.SetUnlinkOnClose(false)
		testutil.Close(t, listener)
		// An unrelated preserved file makes the directory exceed the request scan's
		// cap. Cleanup must still converge without deleting those valuable files.
		testutil.Check(t, os.WriteFile(filepath.Join(dir, name+".keep"), []byte("keep"), 0o600))
	}

	live, _ := transport(t, dir, pairedMac, strings.Repeat("f", 32), func(context.Context, intent.Prompt) approval.Decision { return approval.Approved })
	testutil.Check(t, os.Chtimes(live, time.Now(), time.Now()))
	broker(t, dir)

	deadline := time.Now().Add(5 * time.Second)

	for {
		entries, err := os.ReadDir(dir)
		testutil.Check(t, err)

		if len(entries) < 4096 {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("independent cleanup cannot recover directory cap")
		}

		time.Sleep(10 * time.Millisecond)
	}

	result, err := approval.NewClient(filepath.Join(dir, "approval.sock")).Approve(t.Context(), approval.Request{Reason: "recovered"})
	if err != nil || result.Decision != approval.Approved {
		t.Fatal(result, err)
	}

	keeps, err := filepath.Glob(filepath.Join(dir, "*.keep"))
	testutil.Check(t, err)

	if len(keeps) != 2050 {
		t.Fatal("unrelated files removed")
	}
}

func TestListenerClosePreservesReplacement(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "approval.sock")
	listener, err := approvalforward.Listen(t.Context(), path)
	testutil.Check(t, err)
	testutil.Check(t, os.Rename(path, filepath.Join(dir, "original.sock")))
	testutil.Check(t, os.WriteFile(path, []byte("valuable replacement"), 0o600))
	testutil.Close(t, listener)

	data, err := os.ReadFile(path) // #nosec G304 -- The replacement is controlled by this private disposable fixture.
	testutil.Check(t, err)

	if string(data) != "valuable replacement" {
		t.Fatal("listener shutdown removed a replacement")
	}
}
