// Package native collects explicit review and fresh macOS authentication through
// an embedded helper. Applications need neither an installed CLI nor AppKit setup.
package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalwire"
)

type prompt struct {
	Version int           `json:"version"`
	ID      string        `json:"request_id"`
	Review  intent.Review `json:"review"`
}

// Review waits for a request-bound decision. A nil error alone is not approval.
// Cancellation kills the helper and prevents a late success from being accepted.
// The helper is installed privately from embedded bytes, never from PATH.
func Review(ctx context.Context, review intent.Review) (intent.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, intent.DefaultTimeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return intent.Result{}, err
	}

	if err := validate(review); err != nil {
		return intent.Result{}, err
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return intent.Result{}, err
	}

	p := prompt{Version: 1, ID: hex.EncodeToString(nonce), Review: review}

	helper, err := materialize(ctx)
	if err != nil {
		return intent.Result{RequestID: p.ID, Decision: intent.Unavailable}, err
	}

	if helper == "" {
		return intent.Result{RequestID: p.ID, Decision: intent.Unavailable}, nil
	}

	return run(ctx, helper, p)
}

func validate(r intent.Review) error { return r.Validate() }

func run(ctx context.Context, helper string, p prompt) (intent.Result, error) {
	var data bytes.Buffer

	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(p); err != nil {
		return intent.Result{}, err
	}

	cmd := exec.CommandContext(ctx, helper)
	cmd.Stdin = &data
	output := &boundedOutput{}
	cmd.Stdout = output
	// A broken descendant must not keep a pipe open beyond cancellation.
	cmd.WaitDelay = time.Second
	err := cmd.Run()

	if ctx.Err() != nil {
		return intent.Result{}, ctx.Err()
	}

	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return intent.Result{}, context.DeadlineExceeded
	}

	if err != nil {
		return intent.Result{}, fmt.Errorf("native approval unavailable: %w", err)
	}

	var response approvalwire.Response
	if json.Unmarshal(output.data, &response) != nil || response.Version != 1 || response.ID != p.ID || response.Error != "" {
		return intent.Result{}, errors.New("invalid native approval response")
	}

	decision := intent.Decision(response.Decision)
	switch decision {
	case intent.Approved, intent.Denied, intent.Cancelled, intent.Unavailable:
		return intent.Result{RequestID: p.ID, Decision: decision}, nil
	case intent.TimedOut, intent.Busy:
		return intent.Result{}, errors.New("unexpected native approval decision")
	default:
		return intent.Result{}, errors.New("invalid native approval decision")
	}
}

type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 1024 {
		return 0, errors.New("native response exceeds limit")
	}

	b.data = append(b.data, p...)

	return len(p), nil
}
