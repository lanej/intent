package intent

import (
	"strings"
	"testing"
)

func TestReviewCapacity(t *testing.T) {
	review := Review{Title: strings.Repeat("t", MaxReviewTitle), Summary: strings.Repeat("s", MaxReviewSummary), Details: strings.Repeat("d", MaxReviewDetails)}
	if err := review.Validate(); err != nil {
		t.Fatalf("maximum review rejected: %v", err)
	}

	review.Details += "x"
	if err := review.Validate(); err == nil {
		t.Fatal("oversized review accepted")
	}
}
