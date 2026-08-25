package repository

import (
	"context"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestWebSearchProviderGetDefaultWithPlatform(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:web-search-provider-ext?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.WebSearchProviderEntity{}))

	r := &webSearchProviderRepository{db: db}
	ctx := context.Background()

	mk := func(id string, tenantID uint64, isDefault bool) *types.WebSearchProviderEntity {
		return &types.WebSearchProviderEntity{ID: id, TenantID: tenantID, IsDefault: isDefault}
	}
	require.NoError(t, db.Create(mk("tenant-default", 1, true)).Error)
	require.NoError(t, db.Create(mk("platform-default", 10000, true)).Error)
	require.NoError(t, db.Create(mk("tenant-2-nondefault", 2, false)).Error)

	t.Run("tenant has default -> returns tenant default", func(t *testing.T) {
		p, err := r.GetDefaultWithPlatform(ctx, 1, 10000)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, "tenant-default", p.ID)
	})

	t.Run("tenant has no default -> falls back to platform default", func(t *testing.T) {
		p, err := r.GetDefaultWithPlatform(ctx, 2, 10000)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, "platform-default", p.ID)
	})

	t.Run("neither tenant nor platform has default -> nil", func(t *testing.T) {
		p, err := r.GetDefaultWithPlatform(ctx, 3, 9999)
		require.NoError(t, err)
		require.Nil(t, p)
	})

	t.Run("platformTenantID zero -> no fallback query", func(t *testing.T) {
		p, err := r.GetDefaultWithPlatform(ctx, 2, 0)
		require.NoError(t, err)
		require.Nil(t, p)
	})
}
