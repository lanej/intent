//go:build !windows

// Package approvalconfig configures ordinary SSH; it never opens an SSH transport.
package approvalconfig

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalforward"
	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
	"github.com/lanej/intent/internal/intent"
)

type Profile struct {
	Version     int    `json:"version"`
	Host        string `json:"host"`
	MacID       string `json:"mac_id"`
	RemoteDir   string `json:"remote_directory"`
	Executable  string `json:"executable"`
	LocalSocket string `json:"local_socket"`
}

type serviceRecord struct {
	PID      int    `json:"pid"`
	Identity string `json:"identity"`
	Service  string `json:"service"`
}

type connection struct {
	PID       int    `json:"pid"`
	Identity  string `json:"identity"`
	Transport string `json:"transport"`
}

func root() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(home, ".intent-ssh")

	return dir, approvaldiscovery.PrivateDir(dir, true)
}

func alias(host string) bool {
	if host == "" || len(host) > 200 || strings.HasPrefix(host, "-") {
		return false
	}

	for _, c := range host {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-", c) {
			return false
		}
	}

	return true
}

func randomID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes[:]), nil
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func configQuote(s string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(s) + "\""
}

func writeAtomic(path string, data []byte) error {
	if err := approvaldiscovery.PrivateDir(filepath.Dir(path), false); err != nil {
		return err
	}

	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int64(stat.Uid) != int64(os.Getuid()) {
			return errors.New("preserve unexpected configuration file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".intent-")
	if err != nil {
		return err
	}
	defer cleanup.Remove(file.Name())

	if _, err = file.Write(data); err != nil {
		cleanup.Close(file)
		return err
	}

	if err = file.Close(); err != nil {
		return err
	}

	return os.Rename(file.Name(), path)
}

func readPrivate(path string, value any) error {
	if err := approvaldiscovery.PrivateDir(filepath.Dir(path), false); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 16384 || int64(stat.Uid) != int64(os.Getuid()) {
		return errors.New("invalid private configuration file")
	}

	data, err := os.ReadFile(path) // #nosec G304 -- The bounded regular file is validated inside a private owned directory.
	if err != nil {
		return err
	}

	return json.Unmarshal(data, value)
}

func readProfile(path string) (Profile, error) {
	var p Profile
	if !filepath.IsAbs(path) {
		return p, errors.New("absolute profile path required")
	}

	if err := readPrivate(path, &p); err != nil {
		return p, err
	}

	if p.Version != 1 || !alias(p.Host) || len(p.MacID) != 32 || !filepath.IsAbs(p.Executable) || strings.ContainsAny(p.Executable+p.RemoteDir+path, "%\x00\r\n") {
		return p, errors.New("invalid SSH profile")
	}

	if _, err := hex.DecodeString(p.MacID); err != nil {
		return p, errors.New("invalid Mac routing ID")
	}

	if err := approvalforward.SocketPath(p.LocalSocket); err != nil {
		return p, err
	}

	if err := approvalforward.SocketPath(filepath.Join(p.RemoteDir, p.MacID+"-"+p.MacID+".sock")); err != nil {
		return p, err
	}

	return p, nil
}

// Configure writes one host's private Include. It prints the Include and remote
// service parameters; the caller installs the Include before ordinary Host rules.
// Keeping SSH configuration editing outside this package preserves user options.
func Configure(parent context.Context, host, remoteDir, executable string) error {
	if _, err := processIdentity(os.Getpid()); err != nil {
		return err
	}

	if !alias(host) {
		return errors.New("a literal SSH host alias is required")
	}

	if !filepath.IsAbs(executable) || strings.ContainsAny(host+remoteDir+executable, "%\x00\r\n") {
		return errors.New("absolute executable and safe paths required")
	}

	dir, err := root()
	if err != nil {
		return err
	}

	lock, err := approvalforward.LockWait(parent, dir, "configure.lock")
	if err != nil {
		return err
	}
	defer cleanup.Close(lock)

	macPath := filepath.Join(dir, "mac.json")

	var mac struct {
		ID string `json:"id"`
	}
	if err = readPrivate(macPath, &mac); os.IsNotExist(err) {
		mac.ID, err = randomID()
		if err != nil {
			return err
		}

		data, marshalErr := json.Marshal(mac)
		if marshalErr != nil {
			return marshalErr
		}

		if err = writeAtomic(macPath, data); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	sum := sha256.Sum256([]byte(host))
	id := hex.EncodeToString(sum[:16])

	profileDir := filepath.Join(dir, id)
	if err = approvaldiscovery.PrivateDir(profileDir, true); err != nil {
		return err
	}

	connections := filepath.Join(profileDir, "connections")
	if err = approvaldiscovery.PrivateDir(connections, true); err != nil {
		return err
	}

	profilePath := filepath.Join(profileDir, "profile.json")
	p := Profile{Version: 1, Host: host, MacID: mac.ID, RemoteDir: remoteDir, Executable: executable, LocalSocket: filepath.Join(dir, id+".sock")}

	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// Validate before replacing an existing profile.
	if err = approvalforward.SocketPath(p.LocalSocket); err != nil {
		return err
	}

	if err = approvalforward.SocketPath(filepath.Join(remoteDir, mac.ID+"-"+mac.ID+".sock")); err != nil {
		return err
	}

	if err = writeAtomic(profilePath, data); err != nil {
		return err
	}

	command := quote(executable) + " ssh-prepare --profile " + quote(profilePath) + " --parent $PPID"
	config := fmt.Sprintf("# Generated by Intent: ordinary SSH forwarding\nMatch originalhost %s exec %s\n Include %s\nHost *\n", host, configQuote(command), configQuote(filepath.Join(connections, "*.conf")))

	include := filepath.Join(profileDir, "ssh.conf")
	if err = writeAtomic(include, []byte(config)); err != nil {
		return err
	}

	output := struct{ Include, Profile, MacID, Socket string }{include, profilePath, mac.ID, filepath.Join(remoteDir, "approval.sock")}

	return json.NewEncoder(os.Stdout).Encode(output)
}

// Prepare is a Match exec hook. It only writes metadata; -G and repeated parsing
// never start a service, authenticate, or connect. PID plus start identity makes
// concurrent parsers and PID reuse independent, including ssh's later -f fork.
func Prepare(parent context.Context, path string, pid int) error {
	p, err := readProfile(path)
	if err != nil {
		return err
	}

	identity, err := processIdentity(pid)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)

	lock, err := approvalforward.LockWait(parent, dir, "prepare.lock")
	if err != nil {
		return err
	}
	defer cleanup.Close(lock)

	connections := filepath.Join(dir, "connections")
	if err = approvaldiscovery.PrivateDir(connections, false); err != nil {
		return err
	}

	if err = prune(connections); err != nil {
		return err
	}

	recordPath := filepath.Join(connections, strconv.Itoa(pid)+".json")

	var c connection
	if err = readPrivate(recordPath, &c); err == nil {
		if c.PID != pid || c.Identity != identity {
			return errors.New("parser identity changed during preparation")
		}
	} else if os.IsNotExist(err) {
		transport, randomErr := randomID()
		if randomErr != nil {
			return randomErr
		}

		c = connection{PID: pid, Identity: identity, Transport: transport}

		data, marshalErr := json.Marshal(c)
		if marshalErr != nil {
			return marshalErr
		}

		if err = writeAtomic(recordPath, data); err != nil {
			return err
		}
	} else {
		return err
	}

	if !approvalwire.ValidID(c.Transport) {
		return errors.New("invalid transport identity")
	}

	guard := "test $PPID -eq " + strconv.Itoa(pid) + " && " + quote(p.Executable) + " ssh-match --parent $PPID --identity " + quote(c.Identity)
	connected := quote(p.Executable) + " ssh-connected --profile " + quote(path)
	config := fmt.Sprintf("Match originalhost %s exec %s\n RemoteForward %s %s\n PermitLocalCommand yes\n LocalCommand %s\nHost *\n", p.Host, configQuote(guard), configQuote(filepath.Join(p.RemoteDir, p.MacID+"-"+c.Transport+".sock")), configQuote(p.LocalSocket), connected)

	return writeAtomic(filepath.Join(connections, strconv.Itoa(pid)+".conf"), []byte(config))
}

func prune(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		var c connection

		path := filepath.Join(dir, entry.Name())
		if err = readPrivate(path, &c); err != nil {
			return err
		}

		if strconv.Itoa(c.PID)+".json" != entry.Name() {
			return errors.New("unexpected parser record")
		}

		identity, identityErr := processIdentity(c.PID)
		if identityErr == nil && identity == c.Identity {
			continue
		}
		// A dead parser or a reused PID cannot own future parses. The already
		// parsed SSH child keeps its own forward, so this also supports -f.
		if err = os.Remove(path); err != nil {
			return err
		}

		config := filepath.Join(dir, strconv.Itoa(c.PID)+".conf")
		if err = os.Remove(config); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

func Match(pid int, expected string) error {
	actual, err := processIdentity(pid)
	if err != nil {
		return err
	}

	if expected == "" || actual != expected {
		return errors.New("SSH parser identity differs")
	}

	return nil
}

// Connected starts one persistent profile service and waits only for local
// readiness. LocalCommand runs before SSH's event loop, so it cannot wait for a
// reply through the new SSH connection. It never invokes SSH or a remote helper.
func Connected(parent context.Context, path string) error {
	p, err := readProfile(path)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()

	if approvalforward.Probe(ctx, p.LocalSocket, p.MacID) == nil {
		return nil
	}

	dir := filepath.Dir(p.LocalSocket)
	logPath := filepath.Join(dir, filepath.Base(p.LocalSocket)+".log")

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- The log basename is derived from the profile socket in a private directory; symlinks are refused.
	if err != nil {
		return err
	}
	defer cleanup.Close(file)

	info, err := file.Stat()
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int64(stat.Uid) != int64(os.Getuid()) {
		return errors.New("service log is not private and owned")
	}

	worker := exec.CommandContext(context.WithoutCancel(parent), p.Executable, "serve-local", "--profile", path) // #nosec G204 G702 -- An explicitly configured local executable receives validated arguments; no SSH or shell is started.
	worker.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	worker.Stdout, worker.Stderr = file, file
	if err = worker.Start(); err != nil {
		return err
	}

	if err = worker.Process.Release(); err != nil {
		return err
	}

	for {
		if approvalforward.Probe(ctx, p.LocalSocket, p.MacID) == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("local approval service unavailable: %w", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func Serve(ctx context.Context, path string) error { return serve(ctx, path, intent.Native()) }

func serve(ctx context.Context, path string, authenticate intent.Authenticate) error {
	p, err := readProfile(path)
	if err != nil {
		return err
	}

	dir := filepath.Dir(p.LocalSocket)
	lock, err := approvalforward.Lock(dir, filepath.Base(p.LocalSocket)+".lock")
	if err != nil {
		return err
	}
	defer cleanup.Close(lock)

	listener, err := approvalforward.Listen(ctx, p.LocalSocket)
	if err != nil {
		return err
	}
	defer cleanup.Close(listener)

	serviceID, err := randomID()
	if err != nil {
		return err
	}

	identity, identityErr := processIdentity(os.Getpid())
	if identityErr != nil {
		return identityErr
	}

	metadata, marshalErr := json.Marshal(serviceRecord{PID: os.Getpid(), Identity: identity, Service: serviceID})
	if marshalErr != nil {
		return marshalErr
	}

	status := p.LocalSocket + ".json"
	if err = writeAtomic(status, metadata); err != nil {
		return err
	}
	// Retain diagnostic identity on shutdown; a later owner validates PID and
	// start time. Shutdown must not delete a replacement metadata file.

	service := &intent.Service{Host: p.Host, Session: serviceID, Authenticate: authenticate, Shared: true}

	return service.Serve(ctx, listener)
}
