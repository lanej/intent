package activation

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lanej/intent/internal/testutil"
)

func TestStopAcceptanceFencesRestoreBeforeReply(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native lifecycle owner identity is supported only on macOS and Linux")
	}

	var stops atomic.Int32

	owner, err := New("owned-fixture", runtime.GOOS, runtime.GOARCH, func() { stops.Add(1) })
	if err != nil {
		t.Fatal(err)
	}

	request := Request{Action: "checkpoint", RunID: "11111111-2222-4333-8444-555555555555", Process: owner.Snapshot().Targets[0].Process}
	_, _, err = owner.Control(t.Context(), request)
	testutil.Check(t, err)

	request.Action = "stop"
	snapshot, shutdown, err := owner.Control(t.Context(), request)
	testutil.Check(t, err)

	if !shutdown || !snapshot.Targets[0].Checkpoint.StopSubmitted || stops.Load() != 0 {
		t.Fatal("stop was not retained before reply")
	}

	request.Action = "restore"
	if _, _, err = owner.Control(t.Context(), request); err == nil {
		t.Fatal("concurrent restore reopened stop-submitted owner")
	}

	if _, _, err = owner.Begin(t.Context(), "uncheckpointed-request"); err == nil {
		t.Fatal("stop-submitted owner admitted new approval")
	}

	request.Action = "stop"
	_, shutdown, err = owner.Control(t.Context(), request)
	testutil.Check(t, err)

	if shutdown {
		t.Fatal("duplicate stop repeated shutdown")
	}

	owner.Stop()
	owner.Stop()

	if stops.Load() != 1 || owner.Snapshot().Targets[0].Ready {
		t.Fatal("shutdown repeated or admission fence reopened")
	}
}

func lifecycleFixture(t *testing.T, stop context.CancelFunc) *Runtime {
	t.Helper()

	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native lifecycle owner identity is supported only on macOS and Linux")
	}

	owner, err := New("owned-fixture", runtime.GOOS, runtime.GOARCH, stop)
	if err != nil {
		t.Fatal(err)
	}

	return owner
}

type rejectedControlReply struct {
	net.Conn
	writes *atomic.Int32
}

func (c rejectedControlReply) Write([]byte) (int, error) {
	c.writes.Add(1)
	return 0, io.ErrClosedPipe
}

type rejectedControlReplies struct {
	net.Listener
	writes *atomic.Int32
}

func (l rejectedControlReplies) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return rejectedControlReply{Conn: conn, writes: l.writes}, nil
}

func TestAcceptedStopSurvivesLostControlReply(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stopped := make(chan struct{})

	var stops, writes atomic.Int32

	owner := lifecycleFixture(t, func() {
		stops.Add(1)
		close(stopped)
		cancel()
	})

	request := Request{Action: "checkpoint", RunID: "11111111-2222-4333-8444-555555555555", Process: owner.Snapshot().Targets[0].Process}
	if _, _, err := owner.Control(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- owner.ServeControl(ctx, rejectedControlReplies{Listener: listener, writes: &writes}) }()

	t.Cleanup(func() {
		cancel()

		select {
		case serveErr := <-done:
			if serveErr != nil {
				t.Error(serveErr)
			}
		case <-time.After(time.Second):
			t.Error("owned control server did not exit")
		}
	})

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.Close(t, conn)

	testutil.Check(t, conn.SetDeadline(time.Now().Add(time.Second)))

	request.Action = "stop"
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatal(err)
	}

	if err = json.NewDecoder(conn).Decode(new(Result)); err == nil {
		t.Fatal("failed reply unexpectedly delivered")
	}

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("accepted stop was abandoned after response write failed")
	}

	_, shutdown, err := owner.Control(t.Context(), request)
	if err != nil || shutdown {
		t.Fatalf("duplicate stop: shutdown=%v err=%v", shutdown, err)
	}

	owner.Stop()

	if stops.Load() != 1 || writes.Load() != 1 {
		t.Fatal("accepted shutdown did not execute exactly once after failed reply")
	}

	request.Action = "restore"
	if _, _, err = owner.Control(t.Context(), request); err == nil {
		t.Fatal("lost reply reopened irreversible stop")
	}
}

func TestEveryRestoredCheckpointRejectsDelayedCancellation(t *testing.T) {
	owner := lifecycleFixture(t, nil)
	process := owner.Snapshot().Targets[0].Process

	consumed := []string{
		"11111111-2222-4333-8444-555555555555",
		"22222222-2222-4222-8222-222222222222",
	}
	for _, run := range consumed {
		request := Request{Action: "checkpoint", RunID: run, Process: process}
		if _, _, err := owner.Control(t.Context(), request); err != nil {
			t.Fatal(err)
		}

		request.Action = "restore"
		if _, _, err := owner.Control(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}

	active, done, err := owner.Begin(t.Context(), "new-approval")
	if err != nil {
		t.Fatal(err)
	}
	defer done()

	for _, run := range consumed {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		_, _, err = owner.Control(ctx, Request{Action: "checkpoint", RunID: run, Process: process})

		cancel()

		if err == nil || active.Err() != nil || !owner.Snapshot().Targets[0].Ready {
			t.Fatal("consumed operation cancelled newly admitted approval", run, err)
		}
	}

	done()

	request := Request{Action: "checkpoint", RunID: "33333333-3333-4333-8333-333333333333", Process: process}
	if _, _, err = owner.Control(t.Context(), request); err != nil {
		t.Fatal("fresh operation was refused", err)
	}

	request.Action = "restore"
	if _, _, err = owner.Control(t.Context(), request); err != nil {
		t.Fatal(err)
	}
}
