//go:build !windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/activation"
	"github.com/lanej/intent/internal/approvalconfig"
	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalforward"
	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
)

func writeLifecycleRecord(path string, value any) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".update-")
	if err != nil {
		return err
	}
	defer cleanup.Remove(file.Name())

	if err = json.NewEncoder(file).Encode(value); err != nil {
		cleanup.Close(file)
		return err
	}

	if err = file.Sync(); err != nil {
		cleanup.Close(file)
		return err
	}

	if err = file.Close(); err != nil {
		return err
	}

	return os.Rename(file.Name(), path)
}

func lifecycleStage(directory, expected string) error {
	binary, err := stageArtifact(directory, expected, os.Stdin)
	if err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(map[string]string{"installed_binary": binary, "sha256": expected})
}

func stageArtifact(directory, expected string, input io.Reader) (string, error) {
	if len(expected) != 64 {
		return "", errors.New("selected artifact SHA-256 required")
	}

	if _, err := hex.DecodeString(expected); err != nil {
		return "", err
	}

	if err := approvaldiscovery.PrivateDir(directory, false); err != nil {
		return "", err
	}

	releases := filepath.Join(directory, "releases")
	if err := approvaldiscovery.PrivateDir(releases, true); err != nil {
		return "", err
	}

	release := filepath.Join(releases, expected)
	if err := approvaldiscovery.PrivateDir(release, true); err != nil {
		return "", err
	}

	binary := filepath.Join(release, "intent")
	if info, err := os.Lstat(binary); err == nil {
		digest, digestErr := activation.Digest(binary)
		if digestErr != nil || digest != expected || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
			return "", errors.New("preserve changed immutable Intent release")
		}

		return binary, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	file, err := os.CreateTemp(release, ".binary-")
	if err != nil {
		return "", err
	}
	defer cleanup.Remove(file.Name())

	written, err := io.Copy(file, io.LimitReader(input, (256<<20)+1))
	if err != nil || written > 256<<20 {
		cleanup.Close(file)
		return "", errors.New("intent upload failed or exceeded its binary size bound")
	}

	if err = file.Sync(); err != nil {
		cleanup.Close(file)
		return "", err
	}

	if err = file.Close(); err != nil {
		return "", err
	}

	digest, err := activation.Digest(file.Name())
	if err != nil || digest != expected {
		return "", errors.New("uploaded Intent artifact does not match selected SHA-256")
	}

	if err = os.Chmod(file.Name(), 0o700); err != nil { // #nosec G302 -- This private immutable release must be executable by its owner and grants no group or other access.
		return "", err
	}

	if err = os.Link(file.Name(), binary); err != nil {
		return "", err
	}

	return binary, nil
}

type replacementRecord struct {
	RunID           string             `json:"run_id"`
	Process         activation.Process `json:"process"`
	Artifact        string             `json:"artifact"`
	Phase           string             `json:"phase"`
	StartedPID      int                `json:"started_pid,omitempty"`
	StartedIdentity string             `json:"started_identity,omitempty"`
	Target          string             `json:"target"`
	MacID           string             `json:"mac_id"`
}

func lifecycleReplace(parent context.Context, endpoint, profile, directory string, request activation.Request, expected string) (activation.Result, error) {
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()

	operationLock, err := approvalforward.Lock(filepath.Dir(endpoint), "lifecycle-updates.lock")
	if err != nil {
		return activation.Result{}, err
	}
	defer cleanup.Close(operationLock)

	updates := filepath.Join(filepath.Dir(endpoint), "updates")
	if err = approvaldiscovery.PrivateDir(updates, true); err != nil {
		return activation.Result{}, err
	}

	endpointHash := sha256.Sum256([]byte(endpoint))

	recordDir := filepath.Join(updates, hex.EncodeToString(endpointHash[:]))
	if err = approvaldiscovery.PrivateDir(recordDir, true); err != nil {
		return activation.Result{}, err
	}

	if len(request.RunID) != 36 {
		return activation.Result{}, errors.New("update operation UUID required")
	}

	for _, char := range request.RunID {
		if char != '-' && (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return activation.Result{}, errors.New("invalid update operation UUID")
		}
	}

	recordPath := filepath.Join(recordDir, request.RunID+".json")
	if info, recordErr := os.Lstat(recordPath); recordErr == nil {
		stat, owned := info.Sys().(*syscall.Stat_t)
		if !owned || int64(stat.Uid) != int64(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 16384 {
			return activation.Result{}, errors.New("unexpected retained update receipt")
		}

		file, readErr := os.OpenFile(recordPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- The validated UUID selects only an owner-private native update receipt.
		if readErr != nil {
			return activation.Result{}, readErr
		}

		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			cleanup.Close(file)
			return activation.Result{}, errors.New("retained receipt changed during inspection")
		}

		var retained replacementRecord

		readErr = json.NewDecoder(io.LimitReader(file, 16385)).Decode(&retained)
		cleanup.Close(file)

		if readErr != nil || retained.RunID != request.RunID || retained.Process != request.Process || retained.Artifact != expected {
			return activation.Result{}, errors.New("retained update receipt belongs to another selection")
		}

		current, inspectErr := activation.Call(ctx, endpoint, activation.Request{Action: "inventory"})
		if inspectErr == nil && retained.StartedPID != 0 && current.Targets[0].Process.PID == retained.StartedPID && retained.StartedIdentity != "" && current.Targets[0].Process.StartIdentity == retained.StartedIdentity &&
			current.Targets[0].RunningIdentity != nil && *current.Targets[0].RunningIdentity == expected && current.Targets[0].Process != request.Process &&
			current.Targets[0].Target == retained.Target && current.Targets[0].MacID == retained.MacID && current.Targets[0].Ready {
			current.Targets[0].ExpectedIdentity = &expected
			return current, nil
		}

		return activation.Result{}, errors.New("replacement outcome unknown; inspect retained operation instead of relaunching")
	} else if !os.IsNotExist(recordErr) {
		return activation.Result{}, recordErr
	}

	before, err := activation.Call(ctx, endpoint, activation.Request{Action: "inventory"})
	if err != nil {
		return activation.Result{}, err
	}

	original := before.Targets[0]
	if original.Process != request.Process || original.Checkpoint == nil || original.Checkpoint.State != "confirmed" || original.Checkpoint.RunID != request.RunID || !approvalwire.ValidID(original.MacID) {
		return activation.Result{}, errors.New("matching confirmed owner checkpoint and pairing required")
	}

	args := []string{"serve-remote", "--directory", directory, "--mac-id", original.MacID}
	serviceLockName := "broker.lock"

	if profile != "" {
		value, profileErr := approvalconfig.LifecycleProfileAt(profile)
		if profileErr != nil || value.MacID != original.MacID || value.LocalSocket != endpoint {
			return activation.Result{}, errors.New("local profile pairing or endpoint changed")
		}

		args = []string{"serve-local", "--profile", profile}
		serviceLockName = filepath.Base(endpoint) + ".lock"
	}

	executable, err := os.Executable()
	if err != nil {
		return activation.Result{}, err
	}

	source, err := os.Open(executable) // #nosec G304 -- The native owner stages only its own selected executable, never request-selected paths.
	if err != nil {
		return activation.Result{}, err
	}

	binaryDigest, digestErr := activation.Digest(executable)
	if digestErr != nil {
		cleanup.Close(source)
		return activation.Result{}, digestErr
	}

	immutable, stageErr := stageArtifact(filepath.Dir(endpoint), binaryDigest, source)
	cleanup.Close(source)

	if stageErr != nil {
		return activation.Result{}, stageErr
	}

	record := replacementRecord{RunID: request.RunID, Process: request.Process, Artifact: expected, Phase: "stop-requested", Target: original.Target, MacID: original.MacID}
	if err = writeLifecycleRecord(recordPath, record); err != nil {
		return activation.Result{}, err
	}

	request.Action = "stop"
	if _, err = activation.Call(ctx, endpoint, request); err != nil {
		return activation.Result{}, errors.New("old service stop outcome unknown; do not relaunch")
	}

	record.Phase = "stop-confirmed"
	if err = writeLifecycleRecord(recordPath, record); err != nil {
		return activation.Result{}, err
	}

	for {
		current, inspectErr := activation.Call(ctx, endpoint, activation.Request{Action: "inventory"})
		if inspectErr != nil {
			_, socketErr := os.Lstat(activation.ControlSocket(endpoint))
			if os.IsNotExist(socketErr) {
				serviceLock, lockErr := approvalforward.Lock(filepath.Dir(endpoint), serviceLockName)
				if lockErr == nil {
					cleanup.Close(serviceLock)
					break
				}

				if !errors.Is(lockErr, syscall.EWOULDBLOCK) {
					return activation.Result{}, lockErr
				}
			} else if socketErr != nil {
				return activation.Result{}, socketErr
			}
		}

		if inspectErr == nil && current.Targets[0].Process != request.Process {
			return activation.Result{}, errors.New("another process replaced the checkpointed service")
		}

		select {
		case <-ctx.Done():
			return activation.Result{}, errors.New("old service has not exited; preserve it")
		case <-time.After(20 * time.Millisecond):
		}
	}

	record.Phase = "launch-requested"
	if err = writeLifecycleRecord(recordPath, record); err != nil {
		return activation.Result{}, err
	}

	log, err := os.OpenFile(filepath.Join(recordDir, request.RunID+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- The validated update UUID selects a new exclusive private operation log.
	if err != nil {
		return activation.Result{}, err
	}
	defer cleanup.Close(log)

	child := exec.CommandContext(context.WithoutCancel(ctx), immutable, args...) // #nosec G204 -- Only the selected immutable native executable is relaunched with owner-validated profile or broker arguments.
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Stdin = nil

	child.Stdout, child.Stderr = log, log
	if err = child.Start(); err != nil {
		return activation.Result{}, err
	}

	record.Phase, record.StartedPID = "launch-submitted", child.Process.Pid
	startedIdentity, startErr := activation.ProcessStartIdentity(child.Process.Pid)
	record.StartedIdentity = startedIdentity

	if releaseErr := child.Process.Release(); releaseErr != nil {
		return activation.Result{}, releaseErr
	}

	if err = writeLifecycleRecord(recordPath, record); err != nil {
		return activation.Result{}, err
	}

	if startErr != nil {
		return activation.Result{}, errors.New("replacement process start identity unknown; retain operation")
	}

	for {
		current, inspectErr := activation.Call(ctx, endpoint, activation.Request{Action: "inventory"})
		if inspectErr == nil {
			target := current.Targets[0]
			if target.Process.PID != record.StartedPID || target.Process.StartIdentity != record.StartedIdentity || target.Process == original.Process || target.RunningIdentity == nil || *target.RunningIdentity != expected || target.MacID != original.MacID || !target.Ready {
				return activation.Result{}, errors.New("replacement readiness, artifact, process, or pairing differs")
			}

			record.Phase = "verified"
			if err = writeLifecycleRecord(recordPath, record); err != nil {
				return activation.Result{}, err
			}

			current.Targets[0].ExpectedIdentity = &expected

			return current, nil
		}

		select {
		case <-ctx.Done():
			return activation.Result{}, fmt.Errorf("replacement readiness unknown: %w", inspectErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
