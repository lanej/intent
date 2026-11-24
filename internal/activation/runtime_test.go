package activation

import (
	"runtime"
	"sync/atomic"
	"testing"

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
