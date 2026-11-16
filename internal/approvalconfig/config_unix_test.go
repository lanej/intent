//go:build !windows

package approvalconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lanej/intent/internal/approvalforward"

	"github.com/lanej/intent/internal/testutil"
)

func TestOrdinarySSHParsingPreservesForwardsAndUniqueConnections(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}

	dir, err := os.MkdirTemp("/tmp", "ic-") //nolint:usetesting // macOS pathname sockets require short fixture paths.

	testutil.Check(t, err)
	defer func() { testutil.Check(t, os.RemoveAll(dir)) }()

	binary := filepath.Join(dir, "intent")
	if out, buildErr := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "../../cmd/intent").CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v %s", buildErr, out)
	} // #nosec G204 -- A controlled fixture builds this repository's CLI.

	t.Setenv("HOME", dir)
	testutil.Check(t, Configure(t.Context(), "fixture", filepath.Join(dir, "remote"), binary))

	sum := sha256.Sum256([]byte("fixture"))
	profileDir := filepath.Join(dir, ".intent-ssh", hex.EncodeToString(sum[:16]))
	config := filepath.Join(dir, "ssh_config")
	body := "Include " + configQuote(filepath.Join(profileDir, "ssh.conf")) + "\nHost fixture\n HostName 127.0.0.1\n LocalForward 127.0.0.1:12345 127.0.0.1:9\n RemoteForward /tmp/existing-application.sock 127.0.0.1:9\n ForwardAgent yes\n"
	testutil.Check(t, os.WriteFile(config, []byte(body), 0o600))

	run := func() string {
		out, runErr := exec.CommandContext(t.Context(), "ssh", "-G", "-F", config, "fixture").CombinedOutput() // #nosec G204 -- -G parses a controlled fixture; it cannot establish an SSH transport.
		if runErr != nil {
			t.Errorf("parse: %v %s", runErr, out)
		}

		return string(out)
	}

	results := make(chan string, 2)
	go func() { results <- run() }()
	go func() { results <- run() }()

	first, second := <-results, <-results

	route := func(output string) string {
		var intentRoute string

		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "remoteforward ") && strings.Contains(line, ".intent-ssh") {
				if intentRoute != "" {
					t.Error("duplicate approval forward")
				}

				intentRoute = line
			}
		}

		if intentRoute == "" {
			t.Error("approval forward missing", output)
		}

		for _, expected := range []string{"localforward [127.0.0.1]:12345 [127.0.0.1]:9", "remoteforward /tmp/existing-application.sock [127.0.0.1]:9", "clearallforwardings no", "controlmaster false", "forwardagent yes", "permitlocalcommand yes", "localcommand "} {
			if !strings.Contains(output, expected) {
				t.Error("ordinary SSH option lost", expected, output)
			}
		}

		return intentRoute
	}
	if route(first) == route(second) {
		t.Fatal("concurrent SSH parsers share a remote endpoint")
	}

	if entries, readErr := os.ReadDir(filepath.Join(dir, ".intent-ssh")); readErr != nil {
		t.Fatal(readErr)
	} else {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".sock") {
				t.Fatal("ssh -G started a service")
			}
		}
	}

	installConfig := filepath.Join(dir, "install_config")
	testutil.Check(t, os.WriteFile(installConfig, []byte("Host fixture\n HostName localhost\n"), 0o600))
	testutil.Check(t, Install(t.Context(), "fixture", installConfig))
	installed, readErr := os.ReadFile(installConfig) // #nosec G304 -- Controlled real-helper configuration fixture.
	testutil.Check(t, readErr)
	testutil.Check(t, Install(t.Context(), "fixture", installConfig))
	installedAgain, readErr := os.ReadFile(installConfig) // #nosec G304 -- Controlled real-helper configuration fixture.
	testutil.Check(t, readErr)

	if string(installed) != string(installedAgain) {
		t.Fatal("real Intent hook installation not idempotent")
	}
}

func TestParserReparseAndIdentityGuard(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ir-") //nolint:usetesting // Keep generated socket paths portable.

	testutil.Check(t, err)
	defer func() { testutil.Check(t, os.RemoveAll(dir)) }()

	t.Setenv("HOME", dir)
	testutil.Check(t, Configure(t.Context(), "fixture", filepath.Join(dir, "remote"), "/usr/bin/true"))

	sum := sha256.Sum256([]byte("fixture"))
	profile := filepath.Join(dir, ".intent-ssh", hex.EncodeToString(sum[:16]), "profile.json")
	testutil.Check(t, Prepare(t.Context(), profile, os.Getpid()))
	record := filepath.Join(filepath.Dir(profile), "connections")
	entries, err := os.ReadDir(record)
	testutil.Check(t, err)

	var before connection

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			testutil.Check(t, readPrivate(filepath.Join(record, e.Name()), &before))
		}
	}

	testutil.Check(t, Prepare(t.Context(), profile, os.Getpid()))

	var after connection

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			testutil.Check(t, readPrivate(filepath.Join(record, e.Name()), &after))
		}
	}

	if before != after {
		t.Fatal("reparse changes the transport identity")
	}

	testutil.Check(t, Match(os.Getpid(), before.Identity))

	if Match(os.Getpid(), "wrong") == nil {
		t.Fatal("different start identity accepted")
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err = Connected(ctx, profile); err == nil {
		t.Fatal("non-service executable reported readiness")
	}
}

func TestInstallPreservesUserConfiguration(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ii-") //nolint:usetesting // Profile socket paths must remain short.

	testutil.Check(t, err)
	defer func() { testutil.Check(t, os.RemoveAll(dir)) }()

	t.Setenv("HOME", dir)
	testutil.Check(t, Configure(t.Context(), "fixture", filepath.Join(dir, "remote"), "/usr/bin/true"))

	original := "Host fixture\n HostName localhost\n IdentityAgent /existing/agent.sock\n LocalForward 12345 localhost:9\n"
	source := filepath.Join(dir, "source")
	testutil.Check(t, os.WriteFile(source, []byte(original), 0o600))

	config := filepath.Join(dir, "config")
	testutil.Check(t, os.Symlink(source, config))
	testutil.Check(t, Install(t.Context(), "fixture", config))

	first, err := os.ReadFile(source) // #nosec G304 -- The file is controlled by this disposable fixture.
	testutil.Check(t, err)

	if !strings.HasSuffix(string(first), original) {
		t.Fatal("user settings changed")
	}

	testutil.Check(t, Install(t.Context(), "fixture", config))

	second, err := os.ReadFile(source) // #nosec G304 -- The file is controlled by this disposable fixture.
	testutil.Check(t, err)

	if string(first) != string(second) {
		t.Fatal("installation not idempotent")
	}

	info, err := os.Lstat(config)
	testutil.Check(t, err)

	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("configuration symlink replaced")
	}

	conflicting := original + " LocalCommand echo existing-hook\n PermitLocalCommand yes\n"
	testutil.Check(t, os.WriteFile(source, []byte(conflicting), 0o600))

	if err = Install(t.Context(), "fixture", config); err == nil {
		t.Fatal("existing LocalCommand displaced")
	}

	after, err := os.ReadFile(source) // #nosec G304 -- The file is controlled by this disposable fixture.
	testutil.Check(t, err)

	if string(after) != conflicting {
		t.Fatal("conflicting configuration changed")
	}
}

func TestConcurrentConnectedStartsOneServiceOnDemand(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "is-") //nolint:usetesting // Actual CLI listener needs a portable short socket path.

	testutil.Check(t, err)
	t.Cleanup(func() { testutil.Check(t, os.RemoveAll(dir)) })

	binary := filepath.Join(dir, "intent")
	if out, buildErr := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "../../cmd/intent").CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v %s", buildErr, out)
	} // #nosec G204 -- This disposable fixture builds the repository's CLI.

	t.Setenv("HOME", dir)
	testutil.Check(t, Configure(t.Context(), "fixture", filepath.Join(dir, "remote"), binary))

	sum := sha256.Sum256([]byte("fixture"))
	profile := filepath.Join(dir, ".intent-ssh", hex.EncodeToString(sum[:16]), "profile.json")
	p, err := readProfile(profile)
	testutil.Check(t, err)

	t.Cleanup(func() {
		var owned serviceRecord

		deadline := time.Now().Add(3 * time.Second)

		for {
			readErr := readPrivate(p.LocalSocket+".json", &owned)
			if readErr == nil {
				break
			}

			if time.Now().After(deadline) {
				return
			}

			time.Sleep(10 * time.Millisecond)
		}

		if Match(owned.PID, owned.Identity) != nil {
			return
		}

		if killErr := syscall.Kill(owned.PID, syscall.SIGTERM); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
			t.Error(killErr)
		}

		for {
			_, statErr := os.Lstat(p.LocalSocket)
			if os.IsNotExist(statErr) {
				return
			}

			if time.Now().After(deadline) {
				t.Error("owned detached service survived cleanup")
				return
			}

			time.Sleep(10 * time.Millisecond)
		}
	})

	done := make(chan error, 2)
	go func() { done <- Connected(t.Context(), profile) }()
	go func() { done <- Connected(t.Context(), profile) }()

	testutil.Check(t, <-done)
	testutil.Check(t, <-done)
	testutil.Check(t, approvalforward.Probe(t.Context(), p.LocalSocket, p.MacID))

	var record serviceRecord
	testutil.Check(t, readPrivate(p.LocalSocket+".json", &record))
	// Stop only the process whose UID and start identity match this task-owned
	// CLI service record. An invalid readiness probe cannot display native UI.
	testutil.Check(t, Match(record.PID, record.Identity))
	testutil.Check(t, syscall.Kill(record.PID, syscall.SIGTERM))

	deadline := time.Now().Add(3 * time.Second)

	for {
		_, statErr := os.Lstat(p.LocalSocket)
		if os.IsNotExist(statErr) {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("owned service did not stop")
		}

		time.Sleep(10 * time.Millisecond)
	}
}
