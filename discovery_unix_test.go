//go:build !windows

package intent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanej/intent/internal/testutil"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalwire"
)

func TestSSHDiscoveryWaitsForReadyAndPreservesExplicitSocket(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(SocketEnv, "")
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1000 127.0.0.1 22")
	server := endpoint(t, func(conn net.Conn, r approvalwire.Request) {
		testutil.Check(t, json.NewEncoder(conn).Encode(approvalwire.Response{Version: 1, ID: r.ID, Decision: "approved"}))
	})

	client, err := ClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)

	go func() {
		result, approveErr := client.Approve(context.Background(), Request{Reason: "Approve after setup"})
		if approveErr == nil && result.Decision != Approved {
			approveErr = errors.New("unexpected decision")
		}

		done <- approveErr
	}()

	if err = approvaldiscovery.Publish(approvaldiscovery.Receipt{Version: 1, Session: "test", Socket: server.socketPath}); err != nil {
		t.Fatal(err)
	}

	if err = <-done; err != nil {
		t.Fatal(err)
	}

	t.Setenv(SocketEnv, "/tmp/explicit")

	client, err = ClientFromEnv()
	if err != nil || client.socketPath != "/tmp/explicit" || client.discoveryPath != "" {
		t.Fatal(client, err)
	}
}

func TestDiscoveryWaitIsBoundToCallerContext(t *testing.T) {
	c := &Client{discoveryPath: filepath.Join(t.TempDir(), "missing", "receipt")}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := c.Approve(ctx, Request{Reason: "test"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
