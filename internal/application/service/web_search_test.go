package service

import (
	"context"
	"strings"
	"testing"

	"github.com/Tencent/WeKnora/internal/infrastructure/web_search"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
)

// ---- mocks ----

type mockWSProviderRepo struct {
	byID func(ctx context.Context, tenantID uint64, id string) (*types.WebSearchProviderEntity, error)
}

func (m *mockWSProviderRepo) Create(ctx context.Context, provider *types.WebSearchProviderEntity) error {
	return nil
}
func (m *mockWSProviderRepo) GetByID(ctx context.Context, tenantID uint64, id string) (*types.WebSearchProviderEntity, error) {
	return m.byID(ctx, tenantID, id)
}
func (m *mockWSProviderRepo) GetDefault(ctx context.Context, tenantID uint64) (*types.WebSearchProviderEntity, error) {
	return nil, nil
}
func (m *mockWSProviderRepo) GetDefaultWithPlatform(ctx context.Context, tenantID, platformTenantID uint64) (*types.WebSearchProviderEntity, error) {
	return nil, nil
}
func (m *mockWSProviderRepo) List(ctx context.Context, tenantID uint64) ([]*types.WebSearchProviderEntity, error) {
	return nil, nil
}
func (m *mockWSProviderRepo) Update(ctx context.Context, provider *types.WebSearchProviderEntity) error {
	return nil
}
func (m *mockWSProviderRepo) Delete(ctx context.Context, tenantID uint64, id string) error {
	return nil
}
func (m *mockWSProviderRepo) ClearDefault(ctx context.Context, tenantID uint64, excludeID string) error {
	return nil
}

type fakeWSProvider struct{}

func (f *fakeWSProvider) Name() string { return "tavily" }
func (f *fakeWSProvider) Search(ctx context.Context, query string, maxResults int, includeDate bool) ([]*types.WebSearchResult, error) {
	return []*types.WebSearchResult{{Title: "t", URL: "https://t.com", Snippet: "s"}}, nil
}

func newTestWebSearchService(platformTenantID uint64, repo interfaces.WebSearchProviderRepository) *WebSearchService {
	registry := web_search.NewRegistry()
	registry.Register("tavily", func(params types.WebSearchProviderParameters) (interfaces.WebSearchProvider, error) {
		return &fakeWSProvider{}, nil
	})
	return &WebSearchService{
		registry:         registry,
		providerRepo:     repo,
		timeout:          5,
		platformTenantID: platformTenantID,
	}
}

func wsCtxWithTenant(tenantID uint64) context.Context {
	return context.WithValue(context.Background(), types.TenantIDContextKey, tenantID)
}

// ---- tests ----

// 执行阶段本租户查不到 provider 时，应回退平台租户（agent 解析阶段可能拿到平台 default 的 ID）
func TestResolveProviderFallsBackToPlatformTenant(t *testing.T) {
	repo := &mockWSProviderRepo{
		byID: func(ctx context.Context, tenantID uint64, id string) (*types.WebSearchProviderEntity, error) {
			if tenantID == 10000 && id == "platform-provider" {
				return &types.WebSearchProviderEntity{ID: "platform-provider", TenantID: 10000, Name: "Tavily", Provider: "tavily"}, nil
			}
			return nil, nil
		},
	}
	svc := newTestWebSearchService(10000, repo)
	results, err := svc.Search(wsCtxWithTenant(10012), "platform-provider", &types.WebSearchConfig{MaxResults: 5}, "test")
	if err != nil {
		t.Fatalf("expected platform fallback to succeed, got error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// 本租户有 provider 时优先用本租户，不回退平台
func TestResolveProviderPrefersTenantProvider(t *testing.T) {
	repo := &mockWSProviderRepo{
		byID: func(ctx context.Context, tenantID uint64, id string) (*types.WebSearchProviderEntity, error) {
			if tenantID == 10012 && id == "tenant-provider" {
				return &types.WebSearchProviderEntity{ID: "tenant-provider", TenantID: 10012, Name: "Tavily", Provider: "tavily"}, nil
			}
			return nil, nil
		},
	}
	svc := newTestWebSearchService(10000, repo)
	results, err := svc.Search(wsCtxWithTenant(10012), "tenant-provider", &types.WebSearchConfig{MaxResults: 5}, "test")
	if err != nil {
		t.Fatalf("expected tenant provider to succeed, got error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// 本租户和平台租户都没有 → provider not found
func TestResolveProviderNotFound(t *testing.T) {
	repo := &mockWSProviderRepo{
		byID: func(ctx context.Context, tenantID uint64, id string) (*types.WebSearchProviderEntity, error) {
			return nil, nil
		},
	}
	svc := newTestWebSearchService(10000, repo)
	_, err := svc.Search(wsCtxWithTenant(10012), "missing", &types.WebSearchConfig{MaxResults: 5}, "test")
	if err == nil || !strings.Contains(err.Error(), "web search provider not found") {
		t.Fatalf("expected provider not found error, got: %v", err)
	}
}

// platformTenantID=0（未配置）时不查平台租户
func TestResolveProviderNoPlatformFallbackWhenZero(t *testing.T) {
	repo := &mockWSProviderRepo{
		byID: func(ctx context.Context, tenantID uint64, id string) (*types.WebSearchProviderEntity, error) {
			if tenantID == 10000 && id == "platform-provider" {
				return &types.WebSearchProviderEntity{ID: "platform-provider", TenantID: 10000, Name: "Tavily", Provider: "tavily"}, nil
			}
			return nil, nil
		},
	}
	svc := newTestWebSearchService(0, repo)
	_, err := svc.Search(wsCtxWithTenant(10012), "platform-provider", &types.WebSearchConfig{MaxResults: 5}, "test")
	if err == nil || !strings.Contains(err.Error(), "web search provider not found") {
		t.Fatalf("expected provider not found error when platform fallback disabled, got: %v", err)
	}
}
