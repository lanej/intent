//go:build !windows

package approvalssh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/cleanup"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/intent"
)

// SSHHook is a synchronous LocalCommand hook. The child holds only one-time
// approval authority and outlives this setup command until its SSH master ends.
func SSHHook(ctx context.Context, control string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if _, err := controlIdentity(control); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	logPath, err := hookPath(control, "log")
	if err != nil {
		return err
	}

	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- The path is derived from the validated private SSH session or owned hook directory.
	if err != nil {
		return err
	}
	defer cleanup.Close(log)

	// The detached worker owns the SSH master lifetime, independently of this short hook.
	worker := exec.CommandContext(context.WithoutCancel(ctx), exe, "ssh-broker", "--control", control) // #nosec G204 G702 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.
	worker.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	worker.Stdout, worker.Stderr = log, log
	if err = worker.Start(); err != nil {
		return err
	}
	// LocalCommand runs before the SSH client enters its event loop. Waiting
	// for a mux request here can deadlock it; setup continues in the child.
	return worker.Process.Release()
}

// RunHookBroker is started by SSHHook and monitors the existing SSH master.
func RunHookBroker(ctx context.Context, control string) error {
	return runHookBroker(ctx, control, intent.Native())
}

func mux(ctx context.Context, control string, args ...string) *exec.Cmd {
	options := []string{"-F", "/dev/null", "-S", control, "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ProxyCommand=false", "-o", "RemoteCommand=none"}
	return exec.CommandContext(ctx, "ssh", append(options, args...)...) // #nosec G204 G702 -- Validated SSH or shell parameters are passed as argv; remote helper arguments are shell-quoted.
}

func remoteCommand(ctx context.Context, control string, args ...string) *exec.Cmd {
	command := "intent session"
	for _, arg := range args {
		command += " " + quote(arg)
	}

	return mux(ctx, control, "-T", "--", "intent-mux", command)
}

func hookPath(control, suffix string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(home, ".intent-ssh")
	if err = approvaldiscovery.PrivateDir(dir, true); err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(control))

	return filepath.Join(dir, hex.EncodeToString(hash[:])+"."+suffix), nil
}

func controlIdentity(control string) (string, error) {
	if !filepath.IsAbs(control) || filepath.Clean(control) != control {
		return "", errors.New("SSH control path must be absolute")
	}

	if err := approvaldiscovery.PrivateDir(filepath.Dir(control), false); err != nil {
		return "", err
	}

	info, err := os.Lstat(control) // #nosec G703 -- The path is derived from the validated private SSH session or owned hook directory.
	if err != nil {
		return "", err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || int64(stat.Uid) != int64(os.Getuid()) {
		return "", errors.New("SSH control socket must be owned by this user")
	}

	return fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, info.ModTime().UnixNano()), nil
}

func runHookBroker(parent context.Context, control string, authenticate intent.Authenticate) error {
	identity, err := controlIdentity(control)
	if err != nil {
		return err
	}

	lockPath, err := hookPath(control, "lock")
	if err != nil {
		return err
	}

	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- The path is derived from the validated private SSH session or owned hook directory.
	if err != nil {
		return err
	}
	defer cleanup.Close(lock)

	readyPath, err := hookPath(control, "ready")
	if err != nil {
		return err
	}
	// Multiple simultaneous shell launches may invoke LocalCommand for one mux.
	// Only the owner of the lock creates forwarding; other hooks await readiness.
	deadline := time.Now().Add(25 * time.Second)

	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}

		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}

		if data, e := os.ReadFile(readyPath); e == nil && string(data) == identity { // #nosec G304 -- The path is derived from the validated private SSH session or owned hook directory.
			current, e := controlIdentity(control)
			if e != nil || current != identity {
				return errors.New("SSH master changed during setup")
			}

			return nil
		}

		if !time.Now().Before(deadline) {
			return errors.New("SSH approval setup already in progress")
		}

		select {
		case <-parent.Done():
			return parent.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	defer cleanup.Unlock(int(lock.Fd()))

	cleanup.Remove(readyPath)
	defer cleanup.Remove(readyPath)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// Local connection information comes from the authenticated SSH master, not
	// a caller claim or a hostname interpolated into a LocalCommand shell string.
	startupCtx, stopStartup := context.WithTimeout(ctx, 20*time.Second)
	defer stopStartup()

	infoCommand := mux(startupCtx, control, "-O", "conninfo", "--", "intent-mux")

	var info limitedOutput

	infoCommand.Stdout = &info
	if err = infoCommand.Run(); err != nil {
		return errors.New("SSH approval requires OpenSSH with -O conninfo support (10.3+)")
	}

	host := connectionLabel(string(info.data), control)

	pid, err := connectionPID(string(info.data))
	if err != nil {
		return err
	}

	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}

	session := hex.EncodeToString(nonce)

	dir, err := os.MkdirTemp("/tmp", "intent-ssh-")
	if err != nil {
		return err
	}
	defer cleanup.RemoveAll(dir)

	socket := filepath.Join(dir, "approval.sock")

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer cleanup.Close(listener)

	if err = os.Chmod(socket, 0o600); err != nil {
		return err
	}

	done := make(chan error, 1)

	service := &intent.Service{Host: host, Session: session, Authenticate: authenticate}
	go func() { done <- service.Serve(ctx, listener) }()

	defer func() { cancel(); cleanup.Close(listener); <-done }()

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current, e := controlIdentity(control)
				if e != nil || current != identity {
					cancel()
					return
				}
				// A mux health request is itself a channel and can keep an idle
				// ControlPersist master alive. Signal 0 observes process existence
				// without opening a channel or delivering a signal.
				if syscall.Kill(pid, 0) != nil {
					cancel()
					return
				}
			}
		}
	}()

	defer func() { cancel(); <-monitorDone }()

	prepare := remoteCommand(startupCtx, control, "prepare", session)

	var output limitedOutput

	prepare.Stdout, prepare.Stderr = &output, os.Stderr
	if err = prepare.Run(); err != nil {
		return fmt.Errorf("remote approval setup: %w", err)
	}

	var remote prepared
	if err = json.Unmarshal(output.data, &remote); err != nil || remote.Version != 1 || !validRemoteSocket(remote.Socket) {
		return errors.New("invalid remote approval endpoint")
	}

	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()

		if e := remoteCommand(cleanupCtx, control, "cleanup", session, remote.Socket).Run(); e != nil {
			log.Printf("intent: remote approval directory may remain: %s\n", filepath.Dir(remote.Socket))
		}
	}()
	defer cancel() // Stop UI before potentially slow remote cleanup.

	forward := mux(startupCtx, control, "-O", "forward", "-o", "ExitOnForwardFailure=yes", "-R", remote.Socket+":"+socket, "--", "intent-mux")

	forward.Stderr = os.Stderr
	if err = forward.Run(); err != nil {
		return fmt.Errorf("approval forwarding: %w", err)
	}

	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()

		if cleanupErr := mux(cleanupCtx, control, "-O", "cancel", "-R", remote.Socket+":"+socket, "--", "intent-mux").Run(); cleanupErr != nil {
			log.Print("intent: forwarding cancellation unavailable after transport shutdown")
		}
	}()
	// Publish discovery only after forwarding succeeds, so clients never observe
	// a receipt for a socket that is still being installed.
	if err = remoteCommand(startupCtx, control, "publish", session, remote.Socket).Run(); err != nil {
		return fmt.Errorf("publish approval endpoint: %w", err)
	}

	if err = os.WriteFile(readyPath, []byte(identity), 0o600); err != nil { // #nosec G703 -- The path is derived from the validated private SSH session or owned hook directory.
		return err
	}

	stopStartup()
	<-ctx.Done()

	return nil
}

func connectionLabel(info, control string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "tcp ") && !strings.Contains(line, "UNKNOWN") {
			return line
		}
	}
	// Proxy transports may not expose a peer TCP address. Preserve that missing
	// evidence instead of presenting the local hostname as the remote target.
	return "SSH connection " + filepath.Base(control) + " (destination unavailable through this transport)"
}

func connectionPID(info string) (int, error) {
	line := strings.SplitN(strings.TrimSpace(info), "\n", 2)[0]

	fields := strings.Fields(line)
	if len(fields) < 2 || fields[len(fields)-2] != "pid" {
		return 0, errors.New("SSH master returned no process identity")
	}

	pid, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil || pid <= 1 {
		return 0, errors.New("invalid SSH master process identity")
	}

	return pid, nil
}
