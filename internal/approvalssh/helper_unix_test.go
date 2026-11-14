//go:build !windows

package approvalssh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/intent"
)

// A test-only CLI fixture exercises real detached hook processes without a
// production authentication bypass or external helper path override.
func TestMain(m *testing.M) {
	if os.Getenv("INTENT_HOOK_FAKE_NATIVE") == "1" && len(os.Args) == 4 && os.Args[2] == "--control" {
		var err error
		switch os.Args[1] {
		case "ssh-hook":
			err = SSHHook(context.Background(), os.Args[3])
		case "ssh-broker":
			err = runHookBroker(context.Background(), os.Args[3], func(ctx context.Context, p intent.Prompt) approval.Decision {
				f, e := os.OpenFile(os.Getenv("INTENT_HOOK_PROMPT_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if e != nil {
					return approval.Unavailable
				}
				e = json.NewEncoder(f).Encode(p)
				f.Close()
				if e != nil {
					return approval.Unavailable
				}
				if strings.HasSuffix(p.Reason, "deny") {
					return approval.Denied
				}
				return approval.Approved
			})
		default:
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
