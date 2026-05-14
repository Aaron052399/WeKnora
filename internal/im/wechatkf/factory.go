package wechatkf

import (
	"context"
	"fmt"

	"github.com/Tencent/WeKnora/internal/im"
)

// NewFactory returns an im.AdapterFactory for WeChat Customer Service channels.
// WeChat KF supports webhook mode only.
func NewFactory() im.AdapterFactory {
	return func(factoryCtx context.Context, channel *im.IMChannel, msgHandler func(context.Context, *im.IncomingMessage) error) (im.Adapter, context.CancelFunc, error) {
		creds, err := im.ParseCredentials(channel.Credentials)
		if err != nil {
			return nil, nil, fmt.Errorf("parse wechatkf credentials: %w", err)
		}

		adapter, err := NewAdapter(
			im.GetString(creds, "corp_id"),
			im.GetString(creds, "app_secret"),
			im.GetString(creds, "token"),
			im.GetString(creds, "encoding_aes_key"),
			im.GetString(creds, "api_base_url"),
			im.GetString(creds, "transfer_userid"),
			im.GetString(creds, "transfer_menu_key"),
		)
		if err != nil {
			return nil, nil, err
		}
		return adapter, nil, nil
	}
}
