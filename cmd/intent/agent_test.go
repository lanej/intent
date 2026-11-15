package main

import (
	"testing"
)

func TestAgentInferenceAndOverrides(t *testing.T) {
	for _, test := range []struct {
		name, explicitType, explicitID, wantType, wantID string
		explicit                                         bool
		env                                              map[string]string
		invalid                                          bool
	}{
		{name: "outside agent"},
		{name: "codex thread", env: map[string]string{"CODEX_THREAD_ID": "thread-1", "CODEX_SESSION_ID": "session-2"}, wantType: "codex", wantID: "thread-1"},
		{name: "codex session fallback", env: map[string]string{"CODEX_SESSION_ID": "session-2"}, wantType: "codex", wantID: "session-2"},
		{name: "generic pair", env: map[string]string{"INTENT_AGENT_TYPE": "custom", "INTENT_AGENT_ID": "custom-1", "CODEX_THREAD_ID": "ambient"}, wantType: "custom", wantID: "custom-1"},
		{name: "explicit override", explicit: true, explicitType: "claude-code", explicitID: "explicit", env: map[string]string{"INTENT_AGENT_TYPE": "partial", "CODEX_THREAD_ID": "ambient"}, wantType: "claude-code", wantID: "explicit"},
		{name: "partial flags", explicit: true, explicitType: "custom", env: map[string]string{"CODEX_THREAD_ID": "ambient"}, invalid: true},
		{name: "empty flags", explicit: true, env: map[string]string{"CODEX_THREAD_ID": "ambient"}, invalid: true},
		{name: "partial generic", env: map[string]string{"INTENT_AGENT_ID": "partial", "CODEX_THREAD_ID": "ambient"}, invalid: true},
		{name: "injected metadata", env: map[string]string{"CODEX_THREAD_ID": "a\nAgent: spoof"}, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent, err := requestAgent(test.explicitType, test.explicitID, test.explicit, func(key string) string { return test.env[key] })
			if (err != nil) != test.invalid {
				t.Fatalf("agent=%+v err=%v", agent, err)
			}

			if test.invalid {
				return
			}

			if test.wantType == "" {
				if agent != nil {
					t.Fatalf("invented agent: %+v", agent)
				}

				return
			}

			if agent == nil || agent.Type != test.wantType || agent.ID != test.wantID {
				t.Fatalf("agent=%+v", agent)
			}
		})
	}
}
