package intent

import (
	"errors"
	"strings"
)

// MaxCardText limits the combined UTF-8 text in a ReviewCard before JSON encoding.
const MaxCardText = 64 << 10

// ReviewCard groups trusted application display content. Application names select
// bundled artwork for known apps; no field can load a file or URL. Access contains
// up to three facts, Facts up to 32, and Credentials up to 128. Empty collections
// are omitted. All text together must fit MaxCardText and Review's text rules.
// Credential values must never be supplied here. These claims have no effect on
// authentication methods, expiry enforcement, or the application's authority.
type ReviewCard struct {
	Application string             `json:"application"`
	Subtitle    string             `json:"subtitle"`
	Access      []ReviewFact       `json:"access,omitempty"`
	Credentials []ReviewCredential `json:"credentials,omitempty"`
	Facts       []ReviewFact       `json:"facts,omitempty"`
	NoticeTitle string             `json:"notice_title,omitempty"`
	Notice      string             `json:"notice,omitempty"`
}

// ReviewFact is a labeled display claim. CallerSupplied must be true when the
// value comes from an untrusted caller rather than the trusted application's
// frozen policy or grant. Intent displays this provenance without authenticating it.
type ReviewFact struct {
	Label          string `json:"label"`
	Value          string `json:"value"`
	CallerSupplied bool   `json:"caller_supplied"`
}

// ReviewCredential names a requested credential and its environment variable or
// other visible destination. It contains display metadata, never a secret value.
type ReviewCredential struct {
	Name     string `json:"name"`
	Variable string `json:"variable"`
}

// Validate checks the card's display bounds without changing it or doing I/O.
func (c ReviewCard) Validate() error {
	if strings.TrimSpace(c.Application) == "" || len(c.Application) > MaxReviewTitle || len(c.Access) > 3 || len(c.Facts) > 32 || len(c.Credentials) > 128 {
		return errors.New("invalid review card size or empty application")
	}

	texts := []string{c.Application, c.Subtitle, c.NoticeTitle, c.Notice}
	for _, group := range [][]ReviewFact{c.Access, c.Facts} {
		for _, fact := range group {
			texts = append(texts, fact.Label, fact.Value)
		}
	}

	for _, credential := range c.Credentials {
		texts = append(texts, credential.Name, credential.Variable)
	}

	total := 0
	for _, text := range texts {
		total += len(text)
		if total > MaxCardText {
			return errors.New("review card text exceeds limit")
		}

		if err := (Review{Title: "Card", Summary: text}).Validate(); err != nil {
			return err
		}
	}

	return nil
}
