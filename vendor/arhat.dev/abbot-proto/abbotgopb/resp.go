package abbotgopb

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
)

func NewResponse(resp proto.Marshaler) (*Response, error) {
	if resp == nil {
		return &Response{Kind: RESP_DONE, Body: nil}, nil
	}

	var kind ResponseType
	switch resp.(type) {
	case *ContainerNetworkStatusResponse:
		kind = RESP_CTR_NETWORK_STATUS
	default:
		return nil, fmt.Errorf("unkonw response type")
	}

	data, err := resp.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response body: %w", err)
	}

	return &Response{
		Kind: kind,
		Body: data,
	}, nil
}

func NewContainerNetworkStatusResponse(interfaces []*InterfaceInfo) *ContainerNetworkStatusResponse {
	return &ContainerNetworkStatusResponse{Interfaces: interfaces}
}
