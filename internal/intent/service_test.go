//go:build !windows

package intent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lanej/intent/internal/testutil"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalwire"
)

func startService(t *testing.T, auth Authenticate) string {
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
	var prompts []Prompt

	path := startService(t, func(_ context.Context, p Prompt) approval.Decision {
		prompts = append(prompts, p)
		return approval.Approved
	})
	client := approval.NewClient(path)

	a, err := client.Approve(context.Background(), approval.Request{Reason: "Deploy revision abc123"})
	if err != nil || a.Decision != approval.Approved {
		t.Fatalf("%+v %v", a, err)
	}

	b, err := client.Approve(context.Background(), approval.Request{Reason: "Delete fixture"})
	if err != nil || b.Decision != approval.Approved || a.RequestID == b.RequestID {
		t.Fatalf("%+v %v", b, err)
	}

	if len(prompts) != 2 || prompts[0].Reason != "Deploy revision abc123" || prompts[0].Host != "configured-host" || prompts[0].Session != "local-session" || prompts[0].ID != a.RequestID {
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
