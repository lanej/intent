//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
	"github.com/lanej/intent/internal/testutil"
)

func TestCLITransmitsInferredAgent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "intent-agent-cli-") //nolint:usetesting // Short Unix socket paths are required on macOS.
	testutil.Check(t, err)
	t.Cleanup(func() { testutil.Check(t, os.RemoveAll(dir)) })

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	path := filepath.Join(dir, "a.sock")
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	testutil.Check(t, err)
	t.Cleanup(func() { cleanup.Close(listener) })
	t.Setenv("INTENT_APPROVAL_SOCKET", path)
	t.Setenv("INTENT_AGENT_TYPE", "")
	t.Setenv("INTENT_AGENT_ID", "")
	t.Setenv("CODEX_THREAD_ID", "thread-cli-fixture")

	type received struct {
		request approvalwire.Request
		err     error
	}

	done := make(chan received, 1)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- received{err: acceptErr}
			return
		}
		defer cleanup.Close(conn)

		readErr := conn.SetDeadline(time.Now().Add(3 * time.Second))

		var request approvalwire.Request
		if readErr == nil {
			readErr = approvalwire.Read(conn, &request)
		}

		if readErr == nil {
			readErr = json.NewEncoder(conn).Encode(approvalwire.Response{Version: 1, ID: request.ID, Decision: "denied"})
		}

		done <- received{request: request, err: readErr}
	}()

	var decision decisionExit
	if err := run(ctx, []string{"request", "--reason", "agent fixture"}); !errors.As(err, &decision) || decision.code != 2 {
		t.Fatalf("expected denial: %v", err)
	}

	actual := <-done
	testutil.Check(t, actual.err)

	if actual.request.Agent == nil || actual.request.Agent.Type != "codex" || actual.request.Agent.ID != "thread-cli-fixture" {
		t.Fatalf("identity missing from wire request: %+v", actual.request)
	}
}
