package main

import approval "github.com/lanej/intent"

// Explicit flags replace the whole identity. Never combine half an explicit
// pair with ambient context, which could attribute a request to another agent.
func requestAgent(agentType, agentID string, explicit bool, getenv func(string) string) (*approval.AgentIdentity, error) {
	if !explicit {
		agentType, agentID = getenv("INTENT_AGENT_TYPE"), getenv("INTENT_AGENT_ID")
		if agentType == "" && agentID == "" {
			agentID = getenv("CODEX_THREAD_ID")
			if agentID == "" {
				agentID = getenv("CODEX_SESSION_ID")
			}

			if agentID != "" {
				agentType = "codex"
			}
		}

		if agentType == "" && agentID == "" {
			return nil, nil
		}
	}

	agent := &approval.AgentIdentity{Type: agentType, ID: agentID}
	if err := agent.Validate(); err != nil {
		return nil, err
	}

	return agent, nil
}
