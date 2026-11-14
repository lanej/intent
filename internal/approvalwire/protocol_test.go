package approvalwire

import (
	"bytes"
	"strings"
	"testing"
)

func TestFrameLimitsAndStrictDecoding(t *testing.T) {
	for _, data := range []string{
		"not-json\n",
		"{\"version\":1,\"unexpected\":true}\n",
		"{} {}\n",
		strings.Repeat("x", MaxFrame) + "\n",
		"{}",
	} {
		var r Request
		if Read(strings.NewReader(data), &r) == nil {
			t.Fatalf("accepted malformed frame %.40q", data)
		}
	}
	// Preserve bytes following the first frame for disconnect/pipelining detection.
	data := bytes.NewBufferString("{}\nextra")
	var r Request
	if err := Read(data, &r); err != nil || data.String() != "extra" {
		t.Fatal(data.String(), err)
	}
}
