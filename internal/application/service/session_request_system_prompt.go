package service

import "github.com/Tencent/WeKnora/internal/types"

// applyRequestSystemPromptToAgent overrides the agent's system prompt with the
// request-level value when present (smart-reasoning path). Takes priority over
// the agent config's SystemPrompt applied by buildAgentConfig.
func applyRequestSystemPromptToAgent(req *types.QARequest, agentConfig *types.AgentConfig) {
	if req.SystemPrompt != "" {
		agentConfig.UseCustomSystemPrompt = true
		agentConfig.SystemPrompt = req.SystemPrompt
	}
}

// applyRequestSystemPromptToChatManage overrides the effective RAG system prompt
// with the request-level value when present (quick-answer path). Takes priority
// over the agent config's SystemPrompt applied by applyAgentOverridesToChatManage.
func applyRequestSystemPromptToChatManage(req *types.QARequest, cm *types.ChatManage) {
	if req.SystemPrompt != "" {
		cm.SummaryConfig.Prompt = req.SystemPrompt
	}
}
