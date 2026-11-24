package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"

	"github.com/lanej/intent/internal/activation"
	"github.com/lanej/intent/internal/approvalconfig"
)

func lifecycleCommand(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "artifact" {
		artifact, err := activation.SelectedArtifact()
		if err != nil {
			return err
		}

		return json.NewEncoder(os.Stdout).Encode(artifact)
	}

	if len(args) == 1 && args[0] == "profiles" {
		profiles, err := approvalconfig.LifecycleProfiles()
		if err != nil {
			return err
		}

		return json.NewEncoder(os.Stdout).Encode(profiles)
	}

	if len(args) == 0 {
		return errors.New("usage: intent lifecycle inventory|checkpoint|restore|verify|stop --profile PATH or --directory DIR")
	}

	flags := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	profile := flags.String("profile", "", "existing private local profile")
	directory := flags.String("directory", "", "existing private remote broker directory")
	runID := flags.String("run-id", "", "update operation UUID")
	pid := flags.Int("pid", 0, "inventoried process PID")
	start := flags.String("start-identity", "", "inventoried process start identity")
	native := flags.String("native-id", "", "inventoried native process incarnation")

	sha := flags.String("sha256", "", "selected transfer artifact SHA-256")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	if flags.NArg() != 0 || (*profile == "") == (*directory == "") {
		return errors.New("select one existing --profile or --directory")
	}

	switch args[0] {
	case "inventory", "checkpoint", "restore", "verify", "stop", "restart", "stage":
	default:
		return errors.New("unsupported lifecycle action")
	}

	endpoint, target := filepath.Join(*directory, "approval.sock"), "remote:"+*directory

	if *profile != "" {
		value, err := approvalconfig.LifecycleProfileAt(*profile)
		if err != nil {
			return err
		}

		endpoint, target = value.LocalSocket, "local:"+value.LocalSocket
	}

	expected := activation.ImageIdentity()

	var err error

	if args[0] == "stage" {
		if *profile != "" {
			return errors.New("remote staging requires --directory")
		}

		return lifecycleStage(*directory, *sha)
	}

	request := activation.Request{
		Action: args[0], RunID: *runID,
		Process: activation.Process{PID: *pid, StartIdentity: *start, NativeID: *native, OwnerVerified: true},
	}

	var result activation.Result

	if args[0] == "restart" {
		if expected == nil {
			return errors.New("selected native image identity unavailable")
		}

		result, err = lifecycleReplace(ctx, endpoint, *profile, *directory, request, *expected)
	} else {
		result, err = activation.Call(ctx, endpoint, request)
	}

	if err != nil {
		value := map[string]any{"schema_version": 1, "targets": []any{map[string]any{
			"target": target, "expected_identity": expected, "running_identity": nil,
			"ready": false, "process": nil, "sessions": []any{},
			"reason": "native-checkpoint-control-unavailable: " + err.Error(),
		}}}
		if encodeErr := json.NewEncoder(os.Stdout).Encode(value); encodeErr != nil {
			return encodeErr
		}

		return decisionExit{3}
	}

	result.Targets[0].ExpectedIdentity = expected
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}

	if args[0] == "checkpoint" && (result.Targets[0].Checkpoint == nil || result.Targets[0].Checkpoint.State != "confirmed") {
		return decisionExit{3}
	}

	if args[0] == "verify" && (!result.Targets[0].Ready || !activation.SameImage(result.Targets[0].ExpectedIdentity, result.Targets[0].RunningIdentity)) {
		return decisionExit{3}
	}

	return nil
}
