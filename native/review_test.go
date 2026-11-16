package native

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	approval "github.com/lanej/intent"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("INTENT_TEST_HELPER"); mode != "" {
		var p prompt

		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1048577))
		if err != nil || len(data) > 1048576 || json.Unmarshal(data, &p) != nil {
			os.Exit(2)
		}

		switch mode {
		case "silent":
			os.Exit(0)
		case "wrong-id":
			p.ID = "another-request"
		case "oversized":
			if _, checkErr := fmt.Print(strings.Repeat("x", 2048)); checkErr != nil {
				os.Exit(2)
			}

			os.Exit(0)
		case "blocked":
			time.Sleep(time.Minute)
			os.Exit(0)
		}

		if _, checkErr := fmt.Printf("{\"version\":1,\"request_id\":%q,\"decision\":\"approved\"}\n", p.ID); checkErr != nil {
			os.Exit(2)
		}

		if mode == "extra" {
			if _, checkErr := fmt.Println("extra"); checkErr != nil {
				os.Exit(2)
			}
		}

		if mode == "failed" {
			os.Exit(1)
		}

		os.Exit(0)
	}

	os.Exit(m.Run())
}

func TestNativeRequiresExplicitBoundSuccess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"approved", "silent", "wrong-id", "oversized", "extra", "failed"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("INTENT_TEST_HELPER", mode)

			result, err := run(context.Background(), exe, prompt{ID: strings.Repeat("a", 32)})
			if (err == nil && result.Decision == approval.Approved) != (mode == "approved") {
				t.Fatal(result)
			}
		})
	}
}

func TestNativeStopsOnCancellation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("INTENT_TEST_HELPER", "blocked")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	result, err := run(ctx, exe, prompt{ID: strings.Repeat("a", 32)})
	if err == nil && result.Decision == approval.Approved {
		t.Fatal("cancelled helper approved")
	}
}

func TestReviewValidationAndCancelledContext(t *testing.T) {
	for _, review := range []approval.Review{{}, {Title: "ok", Details: "hidden\u202etext"}, {Title: strings.Repeat("x", 257)}} {
		if _, err := Review(context.Background(), review); err == nil {
			t.Fatal("invalid review accepted")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if result, err := Review(ctx, approval.Review{Title: "No UI"}); err == nil || result.Decision == approval.Approved {
		t.Fatal("cancelled review accepted")
	}
}

func TestAcceptedEscapeHeavyReviewFitsNativeFrame(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("INTENT_TEST_HELPER", "approved")

	review := approval.Review{Title: strings.Repeat("&", 256), Summary: strings.Repeat("<", approval.MaxReviewSummary), Details: strings.Repeat("\t", approval.MaxReviewDetails), Card: &approval.ReviewCard{Application: "A", Subtitle: strings.Repeat("\t", approval.MaxCardText-1)}}
	if validateErr := validate(review); validateErr != nil {
		t.Fatal(validateErr)
	}

	result, err := run(context.Background(), exe, prompt{Version: 1, ID: strings.Repeat("a", 32), Review: review})
	if err != nil || result.Decision != approval.Approved {
		t.Fatalf("valid review rejected: %+v %v", result, err)
	}
}

func TestSnapshotPreservesImmutableDisplay(t *testing.T) {
	original := approval.Review{Title: "Release", Summary: "SSH target: fixture", Details: "Deploy abc123", Agent: &approval.AgentIdentity{Type: "codex", ID: "thread-native-fixture"}, Card: &approval.ReviewCard{Application: "Keylease", Access: []approval.ReviewFact{{Label: "Expires", Value: "12:00"}}, Credentials: []approval.ReviewCredential{{Name: "Token", Variable: "TOKEN"}}, Facts: []approval.ReviewFact{{Label: "Use", Value: "command", CallerSupplied: true}}}}
	frozen := snapshot(original)
	original.Agent.ID = "changed"
	original.Card.Application = "changed"
	original.Card.Access[0].Value = "changed"
	original.Card.Credentials[0].Name = "changed"

	original.Card.Facts[0].Value = "changed"
	if frozen.Agent.ID != "thread-native-fixture" || frozen.Card.Application != "Keylease" || frozen.Card.Access[0].Value != "12:00" || frozen.Card.Credentials[0].Name != "Token" || frozen.Card.Facts[0].Value != "command" || !frozen.Card.Facts[0].CallerSupplied || frozen.Summary != "SSH target: fixture" || frozen.Details != "Deploy abc123" {
		t.Fatal("display snapshot changed")
	}
}
