//go:build darwin

package native

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func TestEmbeddedHelperWithoutInstalledCLI(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Library/Caches"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	const count = 8
	paths := make(chan string, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			path, err := materialize(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			paths <- path
		})
	}
	wg.Wait()
	close(paths)
	first := ""
	for path := range paths {
		if first != "" && first != path {
			t.Fatal("cache did not converge")
		}
		first = path
	}
	if first == "" {
		t.Fatal("helper missing")
	}
	// Invalid input exits before AppKit initialization: execute the actual embedded
	// helper without displaying UI or asking a person to authenticate.
	cmd := exec.Command(first)
	if err := cmd.Run(); err == nil {
		t.Fatal("helper accepted missing request")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
		t.Fatalf("helper failed to load: %v", err)
	}
	check := exec.Command("/usr/bin/codesign", "--verify", "--strict", filepath.Dir(filepath.Dir(filepath.Dir(first))))
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("signature: %v %s", err, out)
	}
	// An altered helper must never execute. Preserve it for inspection.
	if err := os.WriteFile(first, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := materialize(context.Background()); err == nil {
		t.Fatal("accepted altered helper")
	}
}

func TestEmbeddedCacheRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, "Library/Caches")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if err := os.Symlink(t.TempDir(), filepath.Join(base, "dev.joshlane.intent")); err != nil {
		t.Fatal(err)
	}
	if _, err := materialize(context.Background()); err == nil {
		t.Fatal("accepted symlinked cache")
	}
}
