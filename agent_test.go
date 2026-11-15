package intent

import (
	"strings"
	"testing"
)

func TestAgentIdentityValidation(t *testing.T) {
	for _, agent := range []AgentIdentity{
		{Type: "codex", ID: "thread-123"},
		{Type: strings.Repeat("t", 64), ID: strings.Repeat("i", 256)},
	} {
		if err := agent.Validate(); err != nil {
			t.Fatal(err)
		}
	}

	for _, agent := range []AgentIdentity{
		{},
		{Type: "codex"},
		{ID: "thread"},
		{Type: strings.Repeat("x", 65), ID: "thread"},
		{Type: "codex", ID: strings.Repeat("x", 257)},
		{Type: "codex", ID: "agent\nspoofed-row"},
		{Type: "codex", ID: "hidden\u202etext"},
		{Type: "codex", ID: "two words"},
		{Type: "codex", ID: string([]byte{0xff})},
	} {
		if err := agent.Validate(); err == nil {
			t.Fatalf("invalid agent accepted: %+v", agent)
		}

		if err := (Review{Title: "Example", Agent: &agent}).Validate(); err == nil {
			t.Fatal("native review accepted invalid identity")
		}

		if _, err := NewClient("").Approve(t.Context(), Request{Reason: "fixture", Agent: &agent}); err == nil || strings.Contains(err.Error(), "socket") {
			t.Fatalf("invalid identity was not rejected before I/O: %v", err)
		}
	}
}
