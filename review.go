package intent

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Review limits count UTF-8 bytes before JSON encoding.
const (
	MaxReviewTitle   = 256
	MaxReviewSummary = 64 << 10
	MaxReviewDetails = 256 << 10
)

// Review is immutable display content supplied by a trusted application. Intent
// authenticates the human's approval; the application owns what approval permits.
// Put untrusted caller claims in Details and label their provenance in Summary.
type Review struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Details string `json:"details"`
	// Agent is optional caller-supplied context shown with its provenance.
	Agent *AgentIdentity `json:"agent,omitempty"`
	// Card is optional structured display content. Summary and Details remain
	// available in full; none of these fields restrict or authorize an action.
	Card *ReviewCard `json:"card,omitempty"`
}

// Validate checks the review size and text contract without altering its content.
// It performs no I/O or authentication and does not constitute approval.
func (r Review) Validate() error {
	if strings.TrimSpace(r.Title) == "" || len(r.Title) > MaxReviewTitle || len(r.Summary) > MaxReviewSummary || len(r.Details) > MaxReviewDetails {
		return errors.New("invalid review size or empty title")
	}

	for _, s := range []string{r.Title, r.Summary, r.Details} {
		if !utf8.ValidString(s) {
			return errors.New("review must be UTF-8")
		}

		for _, c := range s {
			if (unicode.IsControl(c) && c != '\n' && c != '\t') || unicode.Is(unicode.Cf, c) {
				return errors.New("review contains control or formatting characters")
			}
		}
	}

	if r.Agent != nil {
		if err := r.Agent.Validate(); err != nil {
			return err
		}
	}

	if r.Card != nil {
		return r.Card.Validate()
	}

	return nil
}
