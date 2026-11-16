//go:build darwin

package native_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanej/intent"
	"github.com/lanej/intent/native"
)

// Requires a person; never substitute automated authentication or UI clicks.
func TestHumanAcceptance(t *testing.T) {
	if os.Getenv("INTENT_NATIVE_ACCEPTANCE") != "1" {
		t.Skip("human interaction required; set INTENT_NATIVE_ACCEPTANCE=1")
	}

	data, err := os.ReadFile(filepath.Join("tests", "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}

	var fixture intent.Review
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		reason string
		want   intent.Decision
	}{
		{"Select Approve, then authenticate this synthetic request. No action follows.", intent.Approved},
		{"Use Password, then enter your Mac password for this synthetic request. No action follows.", intent.Approved},
		{"Select Deny for this synthetic request. No action follows.", intent.Denied},
	} {
		t.Run(string(test.want)+"/"+test.reason, func(t *testing.T) {
			review := fixture
			card := *fixture.Card
			review.Card = &card
			review.Title = "Intent acceptance · no action follows"
			review.Card.Subtitle = test.reason
			review.Summary = test.reason + "\n" + fixture.Summary

			result, err := native.Review(context.Background(), review)
			if err != nil || result.Decision != test.want {
				t.Fatalf("want %s; got %+v, %v", test.want, result, err)
			}
		})
	}
}

// Exercises cancellation against the real signed helper before any explicit approval action. It never confirms an approval or automates an authentication.
func TestNativeCancellationAcceptance(t *testing.T) {
	if os.Getenv("INTENT_NATIVE_CANCEL_ACCEPTANCE") != "1" {
		t.Skip("visible native check; set INTENT_NATIVE_CANCEL_ACCEPTANCE=1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := native.Review(ctx, intent.Review{Title: "Intent cancellation check", Summary: "Do not select any action. This synthetic card cancels automatically. No action follows."})
	if !errors.Is(err, context.DeadlineExceeded) || result.Decision == intent.Approved {
		t.Fatalf("cancelled native request: %+v %v", result, err)
	}
}
