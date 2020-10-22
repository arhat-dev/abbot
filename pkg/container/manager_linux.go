package container

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"text/template"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/log"
	"github.com/containernetworking/cni/libcni"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/constant"
)

func NewManager(ctx context.Context, containerNetwork *conf.ContainerNetworkConfig) (*Manager, error) {
	tmpl, err := template.New("").Parse(containerNetwork.Template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cni config template: %w", err)
	}

	cniDataDir, err := filepath.Abs(containerNetwork.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path of container network data dir: %w", err)
	}

	cniConfigFile := filepath.Join(cniDataDir, "config.json")
	templateConfigFile := filepath.Join(cniDataDir, "template-config.json")

	var (
		cniNetworkConfig      *libcni.NetworkConfigList
		cniNetworkConfigBytes []byte
	)
	f, err := os.Stat(cniConfigFile)
	if err == nil {
		if !f.Mode().IsRegular() {
			err = os.RemoveAll(cniConfigFile)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to remove invalid cni network config file %s: %w", cniConfigFile, err,
				)
			}
		} else {
			cniNetworkConfigBytes, err = ioutil.ReadFile(cniConfigFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read cni network config file %s: %w", cniConfigFile, err)
			}

			cniNetworkConfig, err = libcni.ConfListFromBytes(cniNetworkConfigBytes)
			if err != nil {
				// ignore this error, just do not set in memory config
				err = nil                   // nolint:ineffassign
				cniNetworkConfigBytes = nil // nolint:ineffassign
				cniNetworkConfig = nil      // nolint:ineffassign
			}
		}
	}

	loopbackConfig, err := libcni.ConfListFromBytes([]byte(constant.CNILoopbackNetworkConfig))
	if err != nil {
		return nil, fmt.Errorf("failed to parse required internal loopback config")
	}

	return &Manager{
		ctx:    ctx,
		logger: log.Log.WithName("cni"),

		containerDev:       containerNetwork.ContainerInterfaceName,
		cniDataDir:         cniDataDir,
		cniConfigFile:      cniConfigFile,
		templateConfigFile: templateConfigFile,
		cniLookupPaths:     containerNetwork.CNIPluginsLookupPaths,
		cniConfigTemplate:  tmpl,
		mu:                 new(sync.RWMutex),

		cniLoopbackConfig:     loopbackConfig,
		cniNetworkConfigBytes: cniNetworkConfigBytes,
		cniNetworkConfig:      cniNetworkConfig,
	}, nil
}

type Manager struct {
	ctx    context.Context
	logger log.Interface

	containerDev       string
	cniDataDir         string
	cniConfigFile      string
	templateConfigFile string
	cniLookupPaths     []string
	cniConfigTemplate  *template.Template
	mu                 *sync.RWMutex

	cniLoopbackConfig     *libcni.NetworkConfigList
	cniNetworkConfigBytes []byte
	cniNetworkConfig      *libcni.NetworkConfigList
}

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
		config     *abbotgopb.ContainerNetworkConfigResponse
	)

	switch req.Kind {
	case abbotgopb.REQ_ENSURE_CTR_NETWORK_CONFIG:
		statusList, err = m.handleContainerNetworkConfigEnsureReq(ctx, req.Body)
	case abbotgopb.REQ_QUERY_CTR_NETWORK_CONFIG:
		config, err = m.handleContainerNetworkConfigQueryReq(ctx, req.Body)
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
	case config != nil:
		return abbotgopb.NewResponse(config)
	default:
		return abbotgopb.NewResponse(nil)
	}
}
