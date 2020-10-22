package host

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/log"

	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

func (m *Manager) Process(ctx context.Context, req *abbotgopb.Request) (resp *abbotgopb.Response, err error) {
	var config *abbotgopb.HostNetworkConfigResponse
	switch req.Kind {
	case abbotgopb.REQ_ENSURE_HOST_NETWORK_CONFIG:
		config, err = m.handleHostNetworkConfigEnsure(ctx, req.Body)
	case abbotgopb.REQ_QUERY_HOST_NETWORK_CONFIG:
		config, err = m.handleHostNetworkConfigQuery(ctx, req.Body)
	default:
		if m.containerMgr != nil {
			return m.containerMgr.Process(ctx, req)
		}
	}
	if err != nil {
		return nil, err
	}

	switch {
	case config != nil:
		return abbotgopb.NewResponse(config)
	default:
		return nil, fmt.Errorf("invalid result")
	}
}

func (m *Manager) handleHostNetworkConfigQuery(
	ctx context.Context, data []byte,
) (*abbotgopb.HostNetworkConfigResponse, error) {
	_ = ctx

	req := new(abbotgopb.HostNetworkConfigQueryRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HostNetworkConfigQueryRequest: %w", err)
	}

	ret, err := m.checkDeviceStatus(req.GetProviders()...)
	if err != nil {
		return nil, err
	}

	return &abbotgopb.HostNetworkConfigResponse{Actual: ret}, nil
}

func (m *Manager) handleHostNetworkConfigEnsure(
	ctx context.Context, data []byte,
) (*abbotgopb.HostNetworkConfigResponse, error) {
	_ = ctx

	req := new(abbotgopb.HostNetworkConfigEnsureRequest)
	err := req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HostNetworkConfigEnsureRequest: %w", err)
	}

	var (
		add    []*abbotgopb.HostNetworkInterface
		remove []string
	)

	err = func() error {
		m.mu.RLock()
		defer m.mu.RUnlock()

		var (
			provider      string
			expectedNames = make(map[string]struct{})
		)
		// validate name and provider
		for _, exp := range req.Expected {
			name := exp.GetMetadata().GetName()
			p := exp.GetProvider()
			if name == "" {
				return fmt.Errorf("must specify interface name")
			}

			if p == "" {
				return fmt.Errorf("must specify provider")
			}

			expectedNames[name] = struct{}{}

			if provider == "" {
				provider = p
				continue
			}

			if provider != p {
				return fmt.Errorf("must specify same provider in single ensue request")
			}
		}

		for i, exp := range req.Expected {
			name := exp.Metadata.Name

			existingDev, ok := m.hostDevices[name]
			if !ok {
				add = append(add, req.Expected[i])
				continue
			}

			// found interface with this name, check provider
			if p := existingDev.Provider(); p != provider {
				// managed by other controller
				return fmt.Errorf("interface %s already managed by %s", name, p)
			}

			// name and provider are ok, ensure config
			err = existingDev.EnsureConfig(req.Expected[i])
			if err != nil {
				m.logger.I("failed to ensure config of device, will recreate",
					log.String("name", name),
					log.Error(err),
				)

				remove = append(remove, name)
				add = append(add, req.Expected[i])
			}
		}

		// check if any host device with this provider
		for name, dev := range m.hostDevices {
			if dev.Provider() != provider {
				continue
			}

			if _, ok := expectedNames[name]; !ok {
				// this interface is not wanted by this provider
				remove = append(remove, name)
			}
		}

		return nil
	}()
	if err != nil {
		return nil, fmt.Errorf("invalid ensure request: %w", err)
	}

	err = func() error {
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, name := range remove {
			existingDev, ok := m.hostDevices[name]
			if !ok {
				continue
			}

			m.logger.I("deleting running device", log.String("name", name))
			err = existingDev.Delete()
			for i, currentName := range m.hostDeviceNameSeq {
				if currentName == name {
					m.hostDeviceNameSeq = append(m.hostDeviceNameSeq[:i], m.hostDeviceNameSeq[i+1:]...)
					continue
				}
			}
			delete(m.hostDevices, name)
		}

		for _, exp := range add {
			var (
				name = exp.Metadata.Name
				d    types.Driver
				err2 error
			)

			switch exp.Config.(type) {
			case *abbotgopb.HostNetworkInterface_Bridge:
				d, err2 = driver.NewDriver(m.ctx, exp.Provider, constant.DriverBridge, runtime.GOOS, exp)
				if err2 != nil {
					return fmt.Errorf("failed to create bridge interface %s: %w", name, err2)
				}
			case *abbotgopb.HostNetworkInterface_Wireguard:
				d, err2 = driver.NewDriver(m.ctx, exp.Provider, constant.DriverWireguard, runtime.GOOS, exp)
				if err2 != nil {
					return fmt.Errorf("failed to create wireguard interface %s: %w", name, err2)
				}
			default:
				return fmt.Errorf("unknown driver config for interface %s", name)
			}

			m.hostDeviceNameSeq = append(m.hostDeviceNameSeq, d.Name())
			m.hostDevices[d.Name()] = d
		}

		return nil
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure devices: %w", err)
	}

	ifaces, err := m.checkDeviceStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to check device status: %w", err)
	}

	return abbotgopb.NewHostNetworkConfigResponse(ifaces...), nil
}

func (m *Manager) checkDeviceStatus(providerList ...string) ([]*abbotgopb.HostNetworkInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make(map[string]struct{})
	for _, p := range providerList {
		providers[p] = struct{}{}
	}

	all := make(map[string]*abbotgopb.HostNetworkInterface)

	if len(providers) == 0 {
		allIfaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to check all host interfaces: %w", err)
		}

		for _, iface := range allIfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				m.logger.D("failed to check interface addresses",
					log.String("name", iface.Name), log.Error(err),
				)
			}

			var addresses []string
			for _, addr := range addrs {
				addresses = append(addresses, addr.String())
			}

			all[iface.Name] = &abbotgopb.HostNetworkInterface{
				Metadata: &abbotgopb.NetworkInterface{
					Name:            iface.Name,
					Mtu:             int32(iface.MTU),
					HardwareAddress: iface.HardwareAddr.String(),
					Addresses:       addresses,
				},
				Provider: "",
				Config:   &abbotgopb.HostNetworkInterface_Unknown{Unknown: &abbotgopb.DriverUnknown{}},
			}
		}
	}

	var (
		result []*abbotgopb.HostNetworkInterface
	)
	for _, name := range m.hostDeviceNameSeq {
		dev, ok := m.hostDevices[name]
		if !ok {
			return nil, fmt.Errorf("inconsistent sequence and device, interface %s not found", name)
		}

		if len(providers) != 0 {
			// not checking all host interfaces, filter providers
			_, ok = providers[dev.Provider()]
			if !ok {
				continue
			}

			iface, err := net.InterfaceByName(dev.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to check host device %s: %w", name, err)
			}

			cfg, err := dev.GetConfig()
			if err != nil {
				return nil, fmt.Errorf("failed to check device config: %w", err)
			}

			cfg.Metadata.Name = iface.Name
			cfg.Metadata.Mtu = int32(iface.MTU)
			cfg.Metadata.HardwareAddress = iface.HardwareAddr.String()
			cfg.Metadata.Addresses = m.getInterfaceAddresses(iface)
			result = append(result, cfg)
			continue
		}

		// is checking all interfaces
		ret, ok := all[name]
		if !ok {
			m.logger.I("managed interface not found in host", log.String("name", name))
			continue
		}

		cfg, err := dev.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to check device %s config: %w", name, err)
		}

		ret.Provider = dev.Provider()
		ret.Config = cfg.Config
	}

	return result, nil
}

func (m *Manager) getInterfaceAddresses(iface *net.Interface) []string {
	addrs, err := iface.Addrs()
	if err != nil {
		m.logger.D("failed to check interface addresses",
			log.String("name", iface.Name), log.Error(err),
		)
	}

	var addresses []string
	for _, addr := range addrs {
		addresses = append(addresses, addr.String())
	}
	return addresses
}
