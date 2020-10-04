// +build !linux

package container

import (
	"context"
	"fmt"

	"arhat.dev/abbot-proto/abbotgopb"

	"arhat.dev/abbot/pkg/conf"
)

func NewManager(
	_ context.Context,
	_ *conf.ContainerNetworkConfig,
) (abbotgopb.NetworkManagerServer, error) {
	return &Manager{}, nil
}

type Manager struct {
}

func (m *Manager) Process(_ context.Context, _ *abbotgopb.Request) (*abbotgopb.Response, error) {
	return nil, fmt.Errorf("unsupported container network management")
}
