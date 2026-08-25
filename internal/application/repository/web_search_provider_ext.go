package repository

import (
	"context"

	"github.com/Tencent/WeKnora/internal/types"
)

// GetDefaultWithPlatform 返回当前租户的 default web search provider；租户未配置时回退到平台租户的 default provider。
// platformTenantID 为 0 或与 tenantID 相同时跳过回退查询。两边都无 default 时返回 nil。
func (r *webSearchProviderRepository) GetDefaultWithPlatform(ctx context.Context, tenantID, platformTenantID uint64) (*types.WebSearchProviderEntity, error) {
	if provider, err := r.GetDefault(ctx, tenantID); err != nil || provider != nil {
		return provider, err
	}
	if platformTenantID == 0 || platformTenantID == tenantID {
		return nil, nil
	}
	return r.GetDefault(ctx, platformTenantID)
}
