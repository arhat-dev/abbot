package network

import (
	"context"
	"fmt"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/log"
)

func (m *Manager) Process(ctx context.Context, req *abbotgopb.Request) (resp *abbotgopb.Response, err error) {
	logger := m.logger.WithName("request")
	logger.D("processing", log.Any("req", req))
	defer func() {
		if err != nil {
			logger.D("finished with error", log.Error(err))
		}
	}()

	var (
		statusList *abbotgopb.ContainerNetworkStatusListResponse
		status     *abbotgopb.ContainerNetworkStatusResponse
	)

	switch req.Kind {
	case abbotgopb.REQ_ENSURE_CTR_NETWORK_CONFIG:
		statusList, err = m.handleContainerNetworkConfigEnsureReq(ctx, req.Body)
	case abbotgopb.REQ_ENSURE_CTR_NETWORK:
		status, err = m.handleContainerNetworkEnsureReq(ctx, req.Body)
	case abbotgopb.REQ_RESTORE_CTR_NETWORK:
		status, err = m.handleContainerNetworkRestoreReq(ctx, req.Body)
	case abbotgopb.REQ_QUERY_CTR_NETWORK:
		status, err = m.handleContainerNetworkQueryReq(ctx, req.Body)
	case abbotgopb.REQ_DELETE_CTR_NETWORK:
		err = m.handleContainerNetworkDeleteReq(ctx, req.Body)
	default:
		return nil, fmt.Errorf("unknow request type %v", req.Kind)
	}
	if err != nil {
		return nil, err
	}

	switch {
	case statusList != nil:
		return abbotgopb.NewResponse(statusList)
	case status != nil:
		return abbotgopb.NewResponse(status)
	default:
		return abbotgopb.NewResponse(nil)
	}
}
