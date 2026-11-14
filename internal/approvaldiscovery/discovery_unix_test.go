//go:build !windows

package approvaldiscovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectionDiscoveryIsolation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1000 127.0.0.1 22")

	first := Receipt{Version: 1, Session: "first", Socket: "/tmp/first.sock"}
	if err := Publish(first); err != nil {
		t.Fatal(err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}

	actual, err := Read()
	if err != nil || actual != first {
		t.Fatal(actual, err)
	}

	t.Setenv("SSH_CONNECTION", "127.0.0.1 2000 127.0.0.1 22")

	if _, err := Read(); !os.IsNotExist(err) {
		t.Fatalf("borrowed another connection: %v", err)
	}

	second := Receipt{Version: 1, Session: "second", Socket: "/tmp/second.sock"}
	if err := Publish(second); err != nil {
		t.Fatal(err)
	}

	if err := Remove("first"); err != nil {
		t.Fatal(err)
	}

	if actual, err := Read(); err != nil || actual != second {
		t.Fatal(actual, err)
	}

	if err := Remove("second"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal("other connection receipt changed", err)
	}
}

func TestDiscoveryRejectsUnsafeReceipt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1000 127.0.0.1 22")

	r := Receipt{Version: 1, Session: "test", Socket: "/tmp/test.sock"}
	if err := Publish(r); err != nil {
		t.Fatal(err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}

	if err = os.Chmod(path, 0o644); err != nil { // #nosec G302 -- The fixture intentionally needs executable or insecure permissions to exercise this boundary.
		t.Fatal(err)
	}

	if _, err = Read(); err == nil {
		t.Fatal("public receipt accepted")
	}

	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if err = os.Symlink("/tmp", path); err != nil {
		t.Fatal(err)
	}

	if _, err = Read(); err == nil {
		t.Fatal("symlink accepted")
	}

	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if err = os.Chmod(filepath.Dir(path), 0o755); err != nil { // #nosec G302 -- The fixture intentionally needs executable or insecure permissions to exercise this boundary.
		t.Fatal(err)
	}

	if _, err = Read(); err == nil {
		t.Fatal("public directory accepted")
	}
}

func TestConcurrentCleanupCannotDeleteReplacementReceipt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1000 127.0.0.1 22")

	old := Receipt{Version: 1, Session: "old", Socket: "/tmp/old.sock"}
	next := Receipt{Version: 1, Session: "new", Socket: "/tmp/new.sock"}

	if err := Publish(old); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 2)
	started := make(chan struct{}, 2)

	if err := withRegistryLock(func() error {
		go func() { started <- struct{}{}; done <- Remove("old") }()
		go func() { started <- struct{}{}; done <- Publish(next) }()

		<-started
		<-started

		select {
		case err := <-done:
			t.Errorf("registry mutation bypassed held lock: %v", err)
		case <-time.After(20 * time.Millisecond):
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	actual, err := Read()
	if err != nil || actual != next {
		t.Fatalf("replacement receipt lost: %+v %v", actual, err)
	}
}
