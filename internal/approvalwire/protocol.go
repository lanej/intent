// Package approvalwire contains the private, versioned one-time approval protocol.
package approvalwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Version = 1
const MaxFrame = 64 * 1024
const MaxReason = 4 * 1024

type Request struct {
	Version   int    `json:"version"`
	ID        string `json:"request_id"`
	Reason    string `json:"reason"`
	TimeoutMS int64  `json:"timeout_ms"`
}

type Response struct {
	Version  int    `json:"version"`
	ID       string `json:"request_id"`
	Decision string `json:"decision,omitempty"`
	Error    string `json:"error,omitempty"`
}

func ValidReason(reason string) bool {
	if strings.TrimSpace(reason) == "" || len(reason) > MaxReason || !utf8.ValidString(reason) {
		return false
	}
	for _, r := range reason {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func Read(r io.Reader, out any) error {
	// Do not read ahead: the service must observe extra bytes or EOF while its
	// native prompt is pending, including bytes sent in the same socket write.
	data := make([]byte, 0, 1024)
	for {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}
		if b[0] == '\n' {
			break
		}
		data = append(data, b[0])
		if len(data) >= MaxFrame {
			return errors.New("approval frame too large")
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing approval data")
	}
	return nil
}
