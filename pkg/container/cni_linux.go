package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"arhat.dev/abbot-proto/abbotgopb"
	"github.com/containernetworking/cni/libcni"
	"go.uber.org/multierr"
)

type ConfigTemplateVariables struct {
	IPv4Subnet string `json:"ipv4_subnet"`
	IPv6Subnet string `json:"ipv6_subnet"`
}

func (m *Manager) handleContainerNetworkConfigQueryReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkConfigResponse, error) {
	_ = ctx

	req := new(abbotgopb.ContainerNetworkConfigQueryRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContainerNetworkConfigQueryRequest: %w", err)
	}

	varBytes, err := ioutil.ReadFile(m.templateConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &abbotgopb.ContainerNetworkConfigResponse{}, nil
		}

		return nil, fmt.Errorf("failed to read container network config: %w", err)
	}

	v := new(ConfigTemplateVariables)
	err = json.Unmarshal(varBytes, v)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve container network config: %w", err)
	}

	return &abbotgopb.ContainerNetworkConfigResponse{
		Ipv4Subnet: v.IPv4Subnet,
		Ipv6Subnet: v.IPv6Subnet,
	}, nil
}

func (m *Manager) handleContainerNetworkConfigEnsureReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkStatusListResponse, error) {
	_ = ctx

	req := new(abbotgopb.ContainerNetworkConfigEnsureRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContainerNetworkConfigUpdateRequest: %w", err)
	}

	buf := new(bytes.Buffer)
	v := &ConfigTemplateVariables{
		IPv4Subnet: req.Ipv4Subnet,
		IPv6Subnet: req.Ipv6Subnet,
	}

	varBytes, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template variables: %w", err)
	}

	err = ioutil.WriteFile(m.templateConfigFile, varBytes, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to save template variables: %w", err)
	}

	err = m.cniConfigTemplate.Execute(buf, v)
	if err != nil {
		return nil, fmt.Errorf("failed to execute cni config template")
	}

	cniNetworkConfigBytes := buf.Bytes()
	cniNetworkConfig, err := libcni.ConfListFromBytes(cniNetworkConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid cni config bytes generated from template: %w", err)
	}

	// generated valid cni config, save to data dir for future use

	err = ioutil.WriteFile(m.cniConfigFile, cniNetworkConfigBytes, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to persist cni network config to %s: %w", m.cniConfigFile, err)
	}

	m.cacheCNINetworkConfig(cniNetworkConfig, cniNetworkConfigBytes)

	// refresh all container networks
	containerNetworks := make(map[string]*abbotgopb.ContainerNetworkStatusResponse)
	_ = filepath.Walk(m.cniDataDir, func(path string, info os.FileInfo, err2 error) error {
		if info.IsDir() && path != m.cniDataDir {
			return filepath.SkipDir
		}

		name := info.Name()
		if filepath.Ext(name) != "json" {
			return nil
		}

		if name == "config.json" {
			return nil
		}

		if err2 != nil {
			err = multierr.Append(err, err2)
			return nil
		}

		containerID := strings.TrimSuffix(name, ".json")
		req, _, err2 := m.getContainerNetworkConfigSnapshot(containerID)
		if err2 != nil {
			err = multierr.Append(err, err2)
			return nil
		}

		reqData, err2 := req.Marshal()
		if err2 != nil {
			err = multierr.Append(err, err2)
			return nil
		}

		ret, err2 := m.handleContainerNetworkEnsureReq(ctx, reqData)
		if err != nil {
			err = multierr.Append(err, err2)
			return nil
		}

		containerNetworks[containerID] = ret

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to update all existing container networks: %w", err)
	}

	return &abbotgopb.ContainerNetworkStatusListResponse{
		ContainerNetworks: containerNetworks,
	}, nil
}

func (m *Manager) handleContainerNetworkEnsureReq(
	ctx context.Context, data []byte,
) (_ *abbotgopb.ContainerNetworkStatusResponse, err error) {
	req := new(abbotgopb.ContainerNetworkEnsureRequest)
	err = req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContainerNetworkEnsureRequest: %w", err)
	}

	if req.ContainerId == "" {
		return nil, fmt.Errorf("invalid container network ensure request with empty container id")
	}

	if req.Pid == 0 {
		return nil, fmt.Errorf("invalid container network ensure request with no pid")
	}

	cniNetworkConfig, cniNetworkConfigBytes := m.getCachedCNINetworkConfig()
	if cniNetworkConfig == nil {
		return nil, fmt.Errorf("no cni network configured")
	}

	// retrieve old config

	var (
		configUpToDate = false
	)

	oldEnsureReq, oldNetworkConfigBytes, err := m.getContainerNetworkConfigSnapshot(req.ContainerId)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to retrieve existing container network config")
		}
	} else {
		// check if config up to date

		if bytes.Equal(oldNetworkConfigBytes, cniNetworkConfigBytes) {
			configUpToDate = checkEnsureReqEqual(oldEnsureReq, req)
		}
	}

	// if existing config is not up to date, replace it with the latest ensure request
	if !configUpToDate {
		cfg, err2 := newContainerNetworkConfigSnapshot(req, string(cniNetworkConfigBytes))
		if err2 != nil {
			return nil, fmt.Errorf("failed to create container network config record: %w", err2)
		}

		cfgBytes, err2 := json.Marshal(cfg)
		if err2 != nil {
			return nil, fmt.Errorf("failed to marshal container network config bytes: %w", err2)
		}

		configFile := m.getContainerNetworkConfigFile(req.ContainerId)
		err2 = ioutil.WriteFile(configFile, cfgBytes, 0640)
		if err2 != nil {
			return nil, fmt.Errorf("failed to save container network config to %s: %w", configFile, err2)
		}

		defer func() {
			if err != nil {
				// best effort
				err2 := os.Remove(configFile)
				// TODO: log error
				_ = err2
			}
		}()
	}

	cniConfig := m.newCNIConfig()
	netConfig := m.createCNIRuntimeConfig(req)

	// if exiting config is up to date, check if current network meets all these requirements
	if configUpToDate {
		m.logger.D("checking container network")
		err = cniConfig.CheckNetworkList(ctx, cniNetworkConfig, netConfig)
		configUpToDate = err == nil
	}

	// both config file and network are up to date, do nothing
	if configUpToDate {
		var (
			pid    uint32
			ifaces []*abbotgopb.NetworkInterface
		)
		pid, ifaces, err = m.checkContainerNetworkInterfaces(req.Pid, req.ContainerId)
		if err != nil {
			return nil, fmt.Errorf("failed to check contaienr network status: %w", err)
		}

		return &abbotgopb.ContainerNetworkStatusResponse{
			Pid:        pid,
			Interfaces: ifaces,
		}, nil
	}

	m.logger.D("adding container network")
	ifaces, err := m.addContainerNetworks(ctx, cniNetworkConfig, netConfig)
	if err != nil {
		return nil, err
	}

	return &abbotgopb.ContainerNetworkStatusResponse{
		Pid:        req.Pid,
		Interfaces: ifaces,
	}, nil
}

func (m *Manager) handleContainerNetworkRestoreReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkStatusResponse, error) {
	req := new(abbotgopb.ContainerNetworkRestoreRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContainerNetworkRestoreRequest: %w", err)
	}

	if req.ContainerId == "" {
		return nil, fmt.Errorf("invalid restore request with empty container id: %w", err)
	}

	if req.Pid == 0 {
		return nil, fmt.Errorf("invalid restore request with no pid")
	}

	cniNetworkConfig, _ := m.getCachedCNINetworkConfig()

	oldEnsureReq, _, err := m.getContainerNetworkConfigSnapshot(req.ContainerId)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve existing container network config: %w", err)
	}

	oldEnsureReq.Pid = req.Pid

	m.logger.D("adding container network")
	ifaces, err := m.addContainerNetworks(ctx, cniNetworkConfig, m.createCNIRuntimeConfig(oldEnsureReq))
	if err != nil {
		return nil, err
	}

	return &abbotgopb.ContainerNetworkStatusResponse{
		Pid:        req.Pid,
		Interfaces: ifaces,
	}, nil
}

func (m *Manager) handleContainerNetworkDeleteReq(ctx context.Context, data []byte) error {
	req := new(abbotgopb.ContainerNetworkDeleteRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ContainerNetworkDeleteRequest: %w", err)
	}

	if req.ContainerId == "" {
		return fmt.Errorf("invalid delete request with empty container id: %w", err)
	}

	if req.Pid == 0 {
		return fmt.Errorf("invalid delete request with no pid")
	}

	oldEnsureReq, oldCNINetworkConfig, err := m.getContainerNetworkConfigSnapshot(req.ContainerId)
	if err != nil {
		return fmt.Errorf("failed to retrieve container network config: %w", err)
	}

	oldEnsureReq.Pid = req.Pid

	cniNetworkConfig, err := libcni.ConfListFromBytes(oldCNINetworkConfig)
	if err != nil {
		return fmt.Errorf("invalid cni network config snapshot: %w", err)
	}

	m.logger.V("deleting container networks")
	err = m.deleteContainerNetworks(ctx, cniNetworkConfig, m.createCNIRuntimeConfig(oldEnsureReq))
	if err != nil {
		return fmt.Errorf("failed to delete container networks: %w", err)
	}

	return nil
}

func (m *Manager) handleContainerNetworkQueryReq(
	ctx context.Context, data []byte,
) (*abbotgopb.ContainerNetworkStatusResponse, error) {
	_ = ctx

	req := new(abbotgopb.ContainerNetworkQueryRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContainerNetworkQueryRequest: %w", err)
	}

	pid, ifaces, err := m.checkContainerNetworkInterfaces(req.Pid, req.ContainerId)
	if err != nil {
		return nil, fmt.Errorf("failed to check container network interfaces: %w", err)
	}

	return &abbotgopb.ContainerNetworkStatusResponse{
		Pid:        pid,
		Interfaces: ifaces,
	}, nil
}
