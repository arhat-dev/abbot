package abbotgopb

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
)

func NewRequest(req proto.Marshaler) (*Request, error) {
	var kind RequestType
	switch req.(type) {
	case *ContainerNetworkEnsureRequest:
		kind = REQ_ENSURE_CTR_NETWORK
	case *ContainerNetworkQueryRequest:
		kind = REQ_QUERY_CTR_NETWORK
	case *ContainerNetworkDeleteRequest:
		kind = REQ_DELETE_CTR_NETWORK
	case *ContainerNetworkConfigUpdateRequest:
		kind = REQ_UPDATE_CTR_NETWORK_CONFIG
	default:
		return nil, fmt.Errorf("unkonw request type")
	}

	data, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	return &Request{
		Kind: kind,
		Body: data,
	}, nil
}

func NewContainerNetworkEnsureRequest(
	containerID string, pid uint32, capArgs []*CNICapArgs, cniArgs map[string]string,
) *ContainerNetworkEnsureRequest {
	return &ContainerNetworkEnsureRequest{
		ContainerId: containerID,
		Pid:         pid,
		CapArgs:     capArgs,
		CniArgs:     cniArgs,
	}
}

func NewContainerNetworkQueryRequest(pid uint32) *ContainerNetworkQueryRequest {
	return &ContainerNetworkQueryRequest{Pid: pid}
}

func NewContainerNetworkDeleteRequest(containerID string, pid uint32) *ContainerNetworkDeleteRequest {
	return &ContainerNetworkDeleteRequest{
		ContainerId: containerID,
		Pid:         pid,
	}
}

func NewContainerNetworkConfigUpdateRequest(ipv4Subnet, ipv6Subnet string) *ContainerNetworkConfigUpdateRequest {
	return &ContainerNetworkConfigUpdateRequest{
		Ipv4Subnet: ipv4Subnet,
		Ipv6Subnet: ipv6Subnet,
	}
}
