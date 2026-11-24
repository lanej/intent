//go:build !windows

package intent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lanej/intent/internal/activation"
	"github.com/lanej/intent/internal/testutil"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalwire"
)

func startService(t *testing.T, auth Authenticate, lifecycle ...*activation.Runtime) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "kl-test-") //nolint:usetesting // Unix socket fixtures require short paths on macOS.
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "s")

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	service := &Service{Host: "configured-host", Session: "local-session", Authenticate: auth}
	if len(lifecycle) != 0 {
		service.Lifecycle = lifecycle[0]
	}

	go func() { done <- service.Serve(ctx, listener) }()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil {
			t.Error(err)
		}

		testutil.Check(t, os.RemoveAll(dir))
	})

	return path
}

func TestRoundTripAndCallerIsolation(t *testing.T) {
	t.Setenv("INTENT_AGENT_TYPE", "ambient-agent")
	t.Setenv("INTENT_AGENT_ID", "ambient-session")

	var prompts []Prompt

	path := startService(t, func(_ context.Context, p Prompt) approval.Decision {
		prompts = append(prompts, p)
		return approval.Approved
	})
	client := approval.NewClient(path)

	a, err := client.Approve(context.Background(), approval.Request{Reason: "Deploy revision abc123", Agent: &approval.AgentIdentity{Type: "codex", ID: "thread-service-fixture"}})
	if err != nil || a.Decision != approval.Approved {
		t.Fatalf("%+v %v", a, err)
	}

	b, err := client.Approve(context.Background(), approval.Request{Reason: "Delete fixture"})
	if err != nil || b.Decision != approval.Approved || a.RequestID == b.RequestID {
		t.Fatalf("%+v %v", b, err)
	}

	if len(prompts) != 2 || prompts[0].Reason != "Deploy revision abc123" || prompts[0].Host != "configured-host" || prompts[0].Session != "local-session" || prompts[0].ID != a.RequestID || prompts[0].Agent == nil || prompts[0].Agent.Type != "codex" || prompts[0].Agent.ID != "thread-service-fixture" || prompts[1].Agent != nil {
		t.Fatalf("prompts: %+v", prompts)
	}
}

func TestBusyCancellationAndRecovery(t *testing.T) {
	entered := make(chan struct{}, 2)
	cancelled := make(chan struct{}, 2)
	path := startService(t, func(ctx context.Context, _ Prompt) approval.Decision {
		entered <- struct{}{}

		<-ctx.Done()

		cancelled <- struct{}{}

		return approval.Approved
	})
	client := approval.NewClient(path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { _, err := client.Approve(ctx, approval.Request{Reason: "first"}); done <- err }()

	<-entered

	result, err := client.Approve(context.Background(), approval.Request{Reason: "second"})
	if err != nil || result.Decision != approval.Busy {
		t.Fatalf("%+v %v", result, err)
	}

	cancel()

	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("UI not cancelled")
	}
	// handle() may still be releasing the slot; wait for the next accepted prompt.
	deadline := time.Now().Add(time.Second)

	for {
		retryCtx, retryCancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		result, err = client.Approve(retryCtx, approval.Request{Reason: "after cancel"})

		retryCancel()
		// Either side can observe expiry first. Both a client deadline error
		// and a confirmed server timeout prove that the next prompt was accepted.
		if errors.Is(err, context.DeadlineExceeded) || err == nil && result.Decision == approval.TimedOut {
			break
		}

		if err != nil || result.Decision != approval.Busy || time.Now().After(deadline) {
			t.Fatalf("recovery: %+v %v", result, err)
		}
	}

	<-entered
	<-cancelled
}

func TestExpiryNeverDeliversLateApproval(t *testing.T) {
	path := startService(t, func(ctx context.Context, _ Prompt) approval.Decision { <-ctx.Done(); return approval.Approved })

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.Close(t, conn)

	request := approvalwire.Request{Version: 1, ID: strings.Repeat("a", 32), Reason: "expires", TimeoutMS: 20}
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatal(err)
	}

	testutil.Check(t, conn.SetReadDeadline(time.Now().Add(time.Second)))

	var response approvalwire.Response
	if err = approvalwire.Read(conn, &response); err != nil || response.Decision != "timed_out" {
		t.Fatalf("%+v %v", response, err)
	}
}

func TestInvalidRequestsNeverPrompt(t *testing.T) {
	path := startService(t, func(context.Context, Prompt) approval.Decision {
		t.Error("invalid request prompted")
		return approval.Approved
	})

	cases := []approvalwire.Request{
		{Version: 99, ID: strings.Repeat("a", 32), Reason: "action", TimeoutMS: 100},
		{Version: 1, ID: "bad", Reason: "action", TimeoutMS: 100},
		{Version: 1, ID: strings.Repeat("a", 32), Reason: " \n", TimeoutMS: 100},
		{Version: 1, ID: strings.Repeat("a", 32), Reason: "action", TimeoutMS: -1},
		{Version: 1, ID: strings.Repeat("a", 32), Reason: "action", TimeoutMS: 100, Agent: &approvalwire.AgentIdentity{Type: "codex"}},
		{Version: 1, ID: strings.Repeat("a", 32), Reason: "action", TimeoutMS: 100, Agent: &approvalwire.AgentIdentity{Type: "codex", ID: "hidden\u202etext"}},
	}
	for _, r := range cases {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}

		if err = json.NewEncoder(conn).Encode(r); err != nil {
			t.Fatal(err)
		}

		var response approvalwire.Response
		if err = approvalwire.Read(conn, &response); err != nil || response.Error == "" || response.Decision != "" {
			t.Fatalf("%+v %v", response, err)
		}

		testutil.Close(t, conn)
	}
}

func TestDisconnectOrExtraDataCancelsPrompt(t *testing.T) {
	for _, extra := range []bool{false, true} {
		cancelled := make(chan struct{})
		entered := make(chan struct{})
		path := startService(t, func(ctx context.Context, _ Prompt) approval.Decision {
			close(entered)
			<-ctx.Done()
			close(cancelled)

			return approval.Approved
		})

		conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}

		r := approvalwire.Request{Version: 1, ID: strings.Repeat("a", 32), Reason: "action", TimeoutMS: 1000}
		testutil.Check(t, json.NewEncoder(conn).Encode(r))

		<-entered

		if extra {
			var checkedErr5 error

			_, checkedErr5 = conn.Write([]byte("unexpected"))
			testutil.Check(t, checkedErr5)
		} else {
			testutil.Close(t, conn)
		}

		select {
		case <-cancelled:
		case <-time.After(time.Second):
			t.Fatal("prompt survived disconnect/extra data")
		}

		testutil.Close(t, conn)
	}
}

func approvalLifecycleFixture(t *testing.T) *activation.Runtime {
	t.Helper()

	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native lifecycle owner identity is supported only on macOS and Linux")
	}

	owner, err := activation.New("approval-fixture", runtime.GOOS, runtime.GOARCH, nil)
	if err != nil {
		t.Fatal(err)
	}

	return owner
}

func TestLifecycleExpiryRepliesAfterAuthenticationReturns(t *testing.T) {
	owner := approvalLifecycleFixture(t)
	expired := make(chan struct{})
	released := make(chan struct{})

	var releaseOnce sync.Once

	release := func() { releaseOnce.Do(func() { close(released) }) }
	path := startService(t, func(ctx context.Context, _ Prompt) approval.Decision {
		<-ctx.Done()
		close(expired)
		<-released

		return approval.Approved
	}, owner)
	t.Cleanup(release)

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.Close(t, conn)

	request := approvalwire.Request{Version: 1, ID: strings.Repeat("a", 32), Reason: "expires", TimeoutMS: 20}
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-expired:
	case <-time.After(time.Second):
		t.Fatal("authentication did not observe deadline")
	}

	testutil.Check(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

	var response approvalwire.Response

	err = approvalwire.Read(conn, &response)

	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("ordinary deadline closed connection before authentication returned", err)
	}

	testutil.Check(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	release()

	if err = approvalwire.Read(conn, &response); err != nil || response.Decision != "timed_out" {
		t.Fatalf("lost timeout response or delivered late approval: %+v %v", response, err)
	}
}

func TestLifecycleCancellationClosesConnectionBeforeAuthenticationExits(t *testing.T) {
	owner := approvalLifecycleFixture(t)
	entered := make(chan struct{})
	interrupted := make(chan struct{})
	released := make(chan struct{})

	var releaseOnce sync.Once

	release := func() { releaseOnce.Do(func() { close(released) }) }
	path := startService(t, func(ctx context.Context, _ Prompt) approval.Decision {
		close(entered)
		<-ctx.Done()
		close(interrupted)
		<-released

		return approval.Approved
	}, owner)
	t.Cleanup(release)

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.Close(t, conn)

	request := approvalwire.Request{Version: 1, ID: strings.Repeat("b", 32), Reason: "interrupted", TimeoutMS: 5000}
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authentication did not start")
	}

	type checkpointReply struct {
		result activation.Result
		err    error
	}

	checkpoint := make(chan checkpointReply, 1)

	go func() {
		result, _, controlErr := owner.Control(t.Context(), activation.Request{
			Action: "checkpoint", RunID: "11111111-2222-4333-8444-555555555555", Process: owner.Snapshot().Targets[0].Process,
		})
		checkpoint <- checkpointReply{result: result, err: controlErr}
	}()

	select {
	case <-interrupted:
	case <-time.After(time.Second):
		t.Fatal("checkpoint did not interrupt authentication")
	}

	testutil.Check(t, conn.SetReadDeadline(time.Now().Add(time.Second)))

	var response approvalwire.Response
	if err = approvalwire.Read(conn, &response); !errors.Is(err, io.EOF) {
		t.Fatal("lifecycle cancellation did not close the connection immediately", err)
	}

	if owner.Snapshot().Targets[0].Checkpoint.State != "pending" {
		t.Fatal("checkpoint confirmed before authentication exited")
	}

	release()

	select {
	case reply := <-checkpoint:
		if reply.err != nil {
			t.Fatal(reply.err)
		}

		state := reply.result.Targets[0].Checkpoint
		if state.State != "confirmed" || len(state.Interrupted) != 1 || state.Interrupted[0].RequestID != request.ID || state.Interrupted[0].Outcome != "interrupted-or-unknown" {
			t.Fatal("checkpoint lost interrupted request evidence", state)
		}
	case <-time.After(time.Second):
		t.Fatal("checkpoint did not confirm completed interruption")
	}
}
