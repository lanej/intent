//go:build !windows

package approvalssh

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/lanej/intent/internal/approvaldiscovery"
)

func TestPublishPrunesDeadTransportsAndPreservesLiveOrUnknownFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1000 127.0.0.1 22")
	session, dead := prepareTest(t)
	if err := Publish(session, dead); err != nil {
		t.Fatal(err)
	}
	deadReceipt, err := approvaldiscovery.Path()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_CONNECTION", "127.0.0.1 2000 127.0.0.1 22")
	liveSession, live := prepareTest(t)
	listener, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = Publish(liveSession, live); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Dir(dead)); !os.IsNotExist(err) {
		t.Fatalf("dead transport artifact survived: %v", err)
	}
	if _, err = os.Stat(deadReceipt); !os.IsNotExist(err) {
		t.Fatal("dead receipt survived", err)
	}
	liveReceipt, err := approvaldiscovery.Path()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_CONNECTION", "127.0.0.1 3000 127.0.0.1 22")
	unknownSession, unknown := prepareTest(t)
	if err = os.WriteFile(unknown, []byte("valuable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Publish(unknownSession, unknown); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_CONNECTION", "127.0.0.1 4000 127.0.0.1 22")
	nextSession, next := prepareTest(t)
	if err = Publish(nextSession, next); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(liveReceipt); err != nil {
		t.Fatal("live receipt removed", err)
	}
	if data, err := os.ReadFile(unknown); err != nil || string(data) != "valuable" {
		t.Fatal("unknown file changed", err)
	}
}
