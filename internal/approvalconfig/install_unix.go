//go:build !windows

package approvalconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/approvalforward"
	"github.com/lanej/intent/internal/cleanup"
)

// Install prepends one owned Include while preserving the original SSH options.
// Existing LocalCommand is refused rather than overwritten. ssh -G only inspects
// effective configuration; this operation never authenticates or opens transport.
func Install(parent context.Context, host, config string) error {
	dir, err := root()
	if err != nil {
		return err
	}

	lock, lockErr := approvalforward.LockWait(parent, dir, "configure.lock")
	if lockErr != nil {
		return lockErr
	}
	defer cleanup.Close(lock)

	sum := sha256.Sum256([]byte(host))
	profileDir := filepath.Join(dir, hex.EncodeToString(sum[:16]))
	profile := filepath.Join(profileDir, "profile.json")

	p, err := readProfile(profile)
	if err != nil {
		return err
	}

	defaultConfig := config == ""
	if config == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return homeErr
		}

		config = filepath.Join(home, ".ssh", "config")
	}

	if !filepath.IsAbs(config) {
		return errors.New("absolute SSH configuration path required")
	}

	target, err := filepath.EvalSymlinks(config)
	if os.IsNotExist(err) {
		if info, statErr := os.Lstat(config); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("preserve dangling SSH configuration symlink")
		}

		target = config
	} else if err != nil {
		return err
	}

	var original []byte

	parseConfig := "/dev/null"

	if info, statErr := os.Lstat(target); statErr == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || int64(stat.Uid) != int64(os.Getuid()) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("preserve unowned or writable SSH configuration")
		}

		original, err = os.ReadFile(target) // #nosec G304 -- The resolved SSH configuration is an owned regular file and is preserved outside the managed block.
		if err != nil {
			return err
		}

		parseConfig = config
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	args := []string{"-G"}
	if !defaultConfig {
		args = append(args, "-F", parseConfig)
	}

	args = append(args, host)

	output, err := exec.CommandContext(ctx, "ssh", args...).Output() // #nosec G204 -- A literal configured alias and explicit file are passed to OpenSSH's non-connecting configuration inspection mode.
	if err != nil {
		return fmt.Errorf("inspect SSH configuration: %w", err)
	}

	expected := quote(p.Executable) + " ssh-connected --profile " + quote(profile)
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "localcommand ") && strings.TrimPrefix(line, "localcommand ") != expected {
			return errors.New("preserve existing LocalCommand; combine the Intent hook explicitly before installation")
		}
	}

	begin := "# BEGIN Intent SSH " + host + "\n"
	end := "# END Intent SSH " + host + "\n"

	content := string(original)
	if strings.Count(content, begin) != strings.Count(content, end) || strings.Count(content, begin) > 1 {
		return errors.New("malformed managed SSH Include")
	}

	if start := strings.Index(content, begin); start >= 0 {
		finish := strings.Index(content, end)
		if finish < start {
			return errors.New("malformed managed SSH Include")
		}

		content = content[:start] + content[finish+len(end):]
	}

	block := begin + "Include " + configQuote(filepath.Join(profileDir, "ssh.conf")) + "\n" + end

	if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(target), ".intent-config-")
	if err != nil {
		return err
	}
	defer cleanup.Remove(file.Name())

	if _, err = file.WriteString(block + content); err != nil {
		cleanup.Close(file)
		return err
	}

	if err = file.Close(); err != nil {
		return err
	}
	// Detect a concurrent user edit before replacing this snapshot.
	current, readErr := os.ReadFile(target) // #nosec G304 -- The same validated configuration target is compared before its atomic replacement.
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}

	if string(current) != string(original) {
		return errors.New("SSH configuration changed during installation")
	}

	return os.Rename(file.Name(), target)
}
