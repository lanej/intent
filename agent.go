package intent

import (
	"errors"

	"github.com/lanej/intent/internal/approvalwire"
)

// AgentIdentity identifies the calling agent for human review. Type is the agent
// family (for example "codex"); ID is that agent's opaque session or instance ID.
// Both are caller claims, not authenticated identity or authorization evidence.
// Libraries never infer these fields from environment variables.
type AgentIdentity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Validate requires both fields, valid UTF-8, no whitespace/control/formatting
// characters, and at most 64 bytes for Type and 256 bytes for ID.
func (a AgentIdentity) Validate() error {
	if !approvalwire.ValidAgent(a.wire()) {
		return errors.New("agent requires a type (1-64 bytes) and ID (1-256 bytes), without whitespace, control or formatting characters")
	}

	return nil
}

func (a AgentIdentity) wire() *approvalwire.AgentIdentity {
	return &approvalwire.AgentIdentity{Type: a.Type, ID: a.ID}
}
