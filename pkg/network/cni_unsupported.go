// +build !linux

package network

import (
	"arhat.dev/abbot-proto/abbotgopb"
	"context"
	"fmt"
)

func (m *Manager) handleContainerNetworkConfigEnsureReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkStatusListResponse, error) {
	return nil, fmt.Errorf("operation not supported")
}

func (m *Manager) handleContainerNetworkEnsureReq(
	ctx context.Context, data []byte,
) (_ *abbotgopb.ContainerNetworkStatusResponse, err error) {
	return nil, fmt.Errorf("operation not supported")
}

func (m *Manager) handleContainerNetworkRestoreReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkStatusResponse, error) {
	return nil, fmt.Errorf("operation not supported")
}

func (m *Manager) handleContainerNetworkDeleteReq(ctx context.Context, data []byte) error {
	return fmt.Errorf("operation not supported")
}

func (m *Manager) handleContainerNetworkQueryReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkStatusResponse, error) {
	return nil, fmt.Errorf("operation not supported")
}
