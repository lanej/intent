package intent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lanej/intent/internal/testutil"

	"github.com/lanej/intent/internal/approvalwire"
)

func endpoint(t *testing.T, reply func(net.Conn, approvalwire.Request)) *Client {
	t.Helper()

	if os.PathSeparator == '\\' {
		t.Skip("Unix socket approval supports Linux/macOS")
	}

	dir, err := os.MkdirTemp("/tmp", "kl-client-") //nolint:usetesting // Unix socket fixtures require short paths on macOS.
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "s")

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		c, e := l.Accept()
		if e != nil {
			return
		}
		defer testutil.Close(t, c)

		var r approvalwire.Request
		if approvalwire.Read(c, &r) == nil {
			reply(c, r)
		}
	}()

	t.Cleanup(func() { testutil.Close(t, l); <-done; testutil.Check(t, os.RemoveAll(dir)) })

	return NewClient(path)
}

func TestDecisions(t *testing.T) {
	for _, decision := range []Decision{Approved, Denied, Cancelled, TimedOut, Unavailable, Busy} {
		t.Run(string(decision), func(t *testing.T) {
			c := endpoint(t, func(conn net.Conn, r approvalwire.Request) {
				testutil.Check(t, json.NewEncoder(conn).Encode(approvalwire.Response{Version: 1, ID: r.ID, Decision: string(decision)}))
			})

			result, err := c.Approve(context.Background(), Request{Reason: "test"})
			if err != nil || result.Decision != decision || !approvalwire.ValidID(result.RequestID) {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestInvalidResponsesPreserveUncertainty(t *testing.T) {
	for _, mode := range []string{"lost", "wrong-id", "wrong-version", "unknown-decision", "conflicting", "malformed", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			c := endpoint(t, func(conn net.Conn, r approvalwire.Request) {
				response := approvalwire.Response{Version: 1, ID: r.ID, Decision: "approved"}

				switch mode {
				case "lost":
					return
				case "wrong-id":
					response.ID = strings.Repeat("b", 32)
				case "wrong-version":
					response.Version = 99
				case "unknown-decision":
					response.Decision = "yes"
				case "conflicting":
					response.Error = "error"
				case "malformed":
					var checkedErr4 error

					_, checkedErr4 = conn.Write([]byte("bad\n"))
					testutil.Check(t, checkedErr4)

					return
				case "oversized":
					// The client can close as soon as the limit is reached, before
					// the fixture finishes sending the oversized frame.
					if _, writeErr := conn.Write([]byte(strings.Repeat("x", approvalwire.MaxFrame) + "\n")); writeErr != nil && !errors.Is(writeErr, syscall.EPIPE) && !errors.Is(writeErr, syscall.ECONNRESET) {
						t.Error(writeErr)
					}

					return
				}

				testutil.Check(t, json.NewEncoder(conn).Encode(response))
			})

			result, err := c.Approve(context.Background(), Request{Reason: "test"})
			if !errors.Is(err, ErrOutcomeUnknown) || result.Decision == Approved {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestInputAndDiscovery(t *testing.T) {
	t.Setenv(SocketEnv, "")

	if _, err := ClientFromEnv(); err == nil {
		t.Fatal("missing endpoint accepted")
	}

	t.Setenv(SocketEnv, "/tmp/explicit")

	c, err := ClientFromEnv()
	if err != nil || c.socketPath != "/tmp/explicit" {
		t.Fatal(c, err)
	}

	for _, reason := range []string{"", "\t\n", strings.Repeat("x", 4097), "bad\x00reason", "bad\u202ereason", string([]byte{255})} {
		if _, err = c.Approve(context.Background(), Request{Reason: reason}); err == nil {
			t.Fatal("invalid reason accepted")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err = c.Approve(ctx, Request{Reason: "test"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestContextClosesInflightRequest(t *testing.T) {
	closed := make(chan struct{})
	c := endpoint(t, func(conn net.Conn, _ approvalwire.Request) {
		var b [1]byte

		_, readErr := conn.Read(b[:])
		if !errors.Is(readErr, io.EOF) {
			t.Errorf("expected caller disconnect, got %v", readErr)
		}

		close(closed)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	if _, err := c.Approve(ctx, Request{Reason: "test"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("connection remained open")
	}
}

func TestReceivedApprovalRequiresLiveContext(t *testing.T) {
	id := strings.Repeat("a", 32)
	response := approvalwire.Response{Version: 1, ID: id, Decision: "approved"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := decisionResult(ctx, id, response)
	if !errors.Is(err, context.Canceled) || result.Decision == Approved {
		t.Fatalf("cancelled received response: %+v %v", result, err)
	}

	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result, err = decisionResult(ctx, id, response)
	if !errors.Is(err, context.DeadlineExceeded) || result.Decision == Approved {
		t.Fatalf("expired received response: %+v %v", result, err)
	}
}
