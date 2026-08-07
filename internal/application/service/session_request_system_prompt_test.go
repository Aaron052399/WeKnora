package service

import (
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// smart-reasoning path: buildAgentConfig

func TestBuildAgentConfig_RequestSystemPromptOverridesAgent(t *testing.T) {
	svc := newTagTargetSessionService()
	req := &types.QARequest{
		Session: &types.Session{ID: "session-1", TenantID: 100},
		CustomAgent: &types.CustomAgent{
			ID:       "agent-1",
			TenantID: 100,
			Config: types.CustomAgentConfig{
				AgentMode:           types.AgentModeSmartReasoning,
				KBSelectionMode:     "selected",
				KnowledgeBases:      []string{"doc-kb"},
				SystemPrompt:        "agent prompt",
				WebSearchProviderID: "provider-1",
			},
		},
		SystemPrompt: "request prompt",
	}

	agentConfig, err := svc.buildAgentConfig(
		tagTargetContext(), req, &types.Tenant{ID: 100}, 100,
	)
	require.NoError(t, err)
	assert.True(t, agentConfig.UseCustomSystemPrompt)
	assert.Equal(t, "request prompt", agentConfig.SystemPrompt)
}

func TestBuildAgentConfig_EmptyRequestSystemPromptFallsBackToAgent(t *testing.T) {
	svc := newTagTargetSessionService()
	req := &types.QARequest{
		Session: &types.Session{ID: "session-1", TenantID: 100},
		CustomAgent: &types.CustomAgent{
			ID:       "agent-1",
			TenantID: 100,
			Config: types.CustomAgentConfig{
				AgentMode:           types.AgentModeSmartReasoning,
				KBSelectionMode:     "selected",
				KnowledgeBases:      []string{"doc-kb"},
				SystemPrompt:        "agent prompt",
				WebSearchProviderID: "provider-1",
			},
		},
	}

	agentConfig, err := svc.buildAgentConfig(
		tagTargetContext(), req, &types.Tenant{ID: 100}, 100,
	)
	require.NoError(t, err)
	assert.True(t, agentConfig.UseCustomSystemPrompt)
	assert.Equal(t, "agent prompt", agentConfig.SystemPrompt)
}

func TestBuildAgentConfig_NoSystemPromptKeepsDefault(t *testing.T) {
	svc := newTagTargetSessionService()
	req := &types.QARequest{
		Session: &types.Session{ID: "session-1", TenantID: 100},
		CustomAgent: &types.CustomAgent{
			ID:       "agent-1",
			TenantID: 100,
			Config: types.CustomAgentConfig{
				AgentMode:           types.AgentModeSmartReasoning,
				KBSelectionMode:     "selected",
				KnowledgeBases:      []string{"doc-kb"},
				WebSearchProviderID: "provider-1",
			},
		},
	}

	agentConfig, err := svc.buildAgentConfig(
		tagTargetContext(), req, &types.Tenant{ID: 100}, 100,
	)
	require.NoError(t, err)
	assert.False(t, agentConfig.UseCustomSystemPrompt)
	assert.Empty(t, agentConfig.SystemPrompt)
}

// quick-answer path: applyRequestSystemPromptToChatManage

func TestApplyRequestSystemPromptToChatManage_RequestOverridesAgent(t *testing.T) {
	req := &types.QARequest{SystemPrompt: "request prompt"}
	cm := &types.ChatManage{}
	cm.SummaryConfig.Prompt = "agent prompt"

	applyRequestSystemPromptToChatManage(req, cm)

	assert.Equal(t, "request prompt", cm.SummaryConfig.Prompt)
}

func TestApplyRequestSystemPromptToChatManage_EmptyKeepsAgentPrompt(t *testing.T) {
	req := &types.QARequest{}
	cm := &types.ChatManage{}
	cm.SummaryConfig.Prompt = "agent prompt"

	applyRequestSystemPromptToChatManage(req, cm)

	assert.Equal(t, "agent prompt", cm.SummaryConfig.Prompt)
}
