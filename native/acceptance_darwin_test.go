//go:build darwin

package native_test

import (
	"context"
	"os"
	"testing"

	"github.com/lanej/intent"
	"github.com/lanej/intent/native"
)

// Requires a person; never substitute automated authentication or UI clicks.
func TestHumanAcceptance(t *testing.T) {
	if os.Getenv("INTENT_NATIVE_ACCEPTANCE") != "1" {
		t.Skip("human interaction required; set INTENT_NATIVE_ACCEPTANCE=1")
	}

	for _, test := range []struct {
		reason string
		want   intent.Decision
	}{
		{"Authenticate this synthetic request. No action follows.", intent.Approved},
		{"Select Deny for this synthetic request. No action follows.", intent.Denied},
	} {
		result, err := native.Review(context.Background(), intent.Review{Title: "Intent acceptance", Summary: test.reason})
		if err != nil || result.Decision != test.want {
			t.Fatalf("want %s; got %+v, %v", test.want, result, err)
		}
	}
}
