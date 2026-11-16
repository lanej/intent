package intent

import (
	"strings"
	"testing"
)

func TestCardRejectsHiddenClaimsAndExcessiveContent(t *testing.T) {
	for _, card := range []ReviewCard{
		{},
		{Application: string([]byte{0xc2}), Subtitle: string([]byte{0xa0})},
		{Application: "App", Notice: "hidden\u202etext"},
		{Application: "App", Facts: []ReviewFact{{Value: string([]byte{0xff})}}},
		{Application: "App", Credentials: make([]ReviewCredential, 129)},
		{Application: "App", Access: make([]ReviewFact, 4)},
		{Application: "App", Facts: make([]ReviewFact, 33)},
		{Application: "App", Subtitle: strings.Repeat("a", MaxCardText)},
	} {
		if (Review{Title: "Access", Card: &card}).Validate() == nil {
			t.Fatal("invalid card accepted")
		}
	}

	card := ReviewCard{Application: "App", Subtitle: strings.Repeat("a", MaxCardText-3)}
	if err := (Review{Title: "Access", Card: &card}).Validate(); err != nil {
		t.Fatal(err)
	}
}
