package host

import (
	"context"
	"fmt"
	"net"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/log"

	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/drivers"
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

	ret, err := m.checkInterfaces(req.GetProviders()...)
	if err != nil {
		return nil, err
	}

	return &abbotgopb.HostNetworkConfigResponse{Actual: ret}, nil
}

func (m *Manager) handleHostNetworkConfigEnsure(
	ctx context.Context,
	data []byte,
) (
	_ *abbotgopb.HostNetworkConfigResponse,
	err error,
) {
	_ = ctx

	req := new(abbotgopb.HostNetworkConfigEnsureRequest)
	err = req.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HostNetworkConfigEnsureRequest: %w", err)
	}

	// validate request, restrict single non empty provider
	switch req.Provider {
	case "":
		return nil, fmt.Errorf("invalid empty provider")
	case constant.ProviderStatic:
		// protect static interfaces
		return nil, fmt.Errorf("static interfaces are immutable")
	}

	var (
		toAdd    []*abbotgopb.HostNetworkInterface
		toUpdate []*abbotgopb.HostNetworkInterface
		toDelete []string

		expectedNames = make(map[string]struct{})
	)

	m.mu.Lock()
	// validate name and provider, determine actual operation
	{
		for _, exp := range req.Expected {
			name := exp.GetMetadata().GetName()
			if name == "" {
				m.mu.Unlock()
				return nil, fmt.Errorf("invalid empty interface name")
			}

			// here we assume they all share the same provider
			expectedNames[name] = struct{}{}
		}

		for i, exp := range req.Expected {
			name := exp.Metadata.Name

			existingDev, ok := m.hostDevices[name]
			if !ok {
				toAdd = append(toAdd, req.Expected[i])
				continue
			}

			// found interface with this name, check its provider
			if p := existingDev.Provider(); p != req.Provider {
				// managed by other controller
				m.mu.Unlock()
				return nil, fmt.Errorf("interface %s already managed by %s", name, p)
			}

			// name and provider are ok, need to update config
			toUpdate = append(toUpdate, req.Expected[i])
		}

		// check if any host device with this provider but not listed
		// they are no longer wanted by the provider
		for name, dev := range m.hostDevices {
			if dev.Provider() != req.Provider {
				continue
			}

			if _, ok := expectedNames[name]; !ok {
				toDelete = append(toDelete, name)
			}
		}
	}

	// update, remove and add expected interfaces
	{
		var (
			updated []*abbotgopb.HostNetworkInterface
			deleted []*abbotgopb.HostNetworkInterface
			added   []string
		)

		defer func() {
			defer m.mu.Unlock()

			// rollback on error, best effort
			if err == nil {
				return
			}

			// first delete added devices
			for _, name := range added {
				_, _ = m.deleteInterface(name)
			}

			// then add deleted devices
			for _, config := range deleted {
				_, _ = m.addInterface(config)
			}

			// rollback device config
			for _, oldConfig := range updated {
				_, _ = m.updateInterface(oldConfig)
			}
		}()

		for _, newConfig := range toUpdate {
			var oldConfig *abbotgopb.HostNetworkInterface
			oldConfig, err = m.updateInterface(newConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to update config of interface %q: %w", newConfig.Metadata.Name, err)
			}

			updated = append(updated, oldConfig)
		}

		for _, name := range toDelete {
			var oldConfig *abbotgopb.HostNetworkInterface
			oldConfig, err = m.deleteInterface(name)
			if err != nil {
				return nil, fmt.Errorf("failed to delete interface %q: %w", name, err)
			}

			deleted = append(deleted, oldConfig)
		}

		for _, exp := range toAdd {
			var name string
			name, err = m.addInterface(exp)
			if err != nil {
				return nil, fmt.Errorf("failed to add interface: %w", err)
			}

			added = append(added, name)
		}
	}

	ifaces, err := m.checkInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to check device status: %w", err)
	}

	return &abbotgopb.HostNetworkConfigResponse{Actual: ifaces}, nil
}

func (m *Manager) updateInterface(
	config *abbotgopb.HostNetworkInterface,
) (
	prevConfig *abbotgopb.HostNetworkInterface,
	_ error,
) {
	name := config.Metadata.Name
	existingDev, ok := m.hostDevices[name]
	if !ok {
		return nil, fmt.Errorf("unexpected interface %q not found", name)
	}

	prevConfig, err := existingDev.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get old config of interface %q: %w", name, err)
	}

	m.logger.I("updating running interface", log.String("name", name))
	err = existingDev.EnsureConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure config of interface %q: %w", name, err)
	}

	return prevConfig, nil
}

func (m *Manager) deleteInterface(name string) (config *abbotgopb.HostNetworkInterface, _ error) {
	existingDev, ok := m.hostDevices[name]
	if !ok {
		return nil, fmt.Errorf("unexpected interface %q not found", name)
	}

	config, err := existingDev.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get config of interface %q: %w", name, err)
	}

	m.logger.I("deleting running interface", log.String("name", name))
	err = existingDev.Delete(true)
	if err != nil {
		return nil, fmt.Errorf("failed to delete existing interface: %w", err)
	}

	// update sequence and index
	for i, currentName := range m.hostDeviceNameSeq {
		if currentName == name {
			m.hostDeviceNameSeq = append(m.hostDeviceNameSeq[:i], m.hostDeviceNameSeq[i+1:]...)
			continue
		}
	}
	delete(m.hostDevices, name)

	return config, nil
}

func (m *Manager) addInterface(config *abbotgopb.HostNetworkInterface) (string, error) {
	var (
		name = config.Metadata.Name
		d    drivers.Interface
		err  error
	)

	switch config.Config.(type) {
	case *abbotgopb.HostNetworkInterface_Bridge:
		d, err = drivers.NewDriver(m.ctx, config.Provider, constant.DriverBridge, config)
		if err != nil {
			return "", fmt.Errorf("failed to create bridge interface %s: %w", name, err)
		}
	case *abbotgopb.HostNetworkInterface_Wireguard:
		d, err = drivers.NewDriver(m.ctx, config.Provider, constant.DriverWireguard, config)
		if err != nil {
			return "", fmt.Errorf("failed to create wireguard interface %s: %w", name, err)
		}
	default:
		return "", fmt.Errorf("unknown driver config for interface %s", name)
	}

	err = d.Ensure(true)
	if err != nil {
		return "", fmt.Errorf("failed to bring interface %q up: %w", d.Name(), err)
	}

	name = d.Name()

	m.hostDeviceNameSeq = append(m.hostDeviceNameSeq, name)
	m.hostDevices[name] = d

	return name, nil
}

func (m *Manager) checkInterfaces(providerList ...string) ([]*abbotgopb.HostNetworkInterface, error) {
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
