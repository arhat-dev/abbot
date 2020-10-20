package host

import (
	"context"
	"fmt"
	"runtime"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/log"

	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

func (m *Manager) Process(ctx context.Context, req *abbotgopb.Request) (resp *abbotgopb.Response, err error) {
	var status *abbotgopb.HostNetworkStatusResponse
	switch req.Kind {
	case abbotgopb.REQ_ENSURE_HOST_NETWORK_CONFIG:
		status, err = m.handleHostNetworkConfigEnsure(ctx, req.Body)
	default:
		if m.containerMgr != nil {
			return m.containerMgr.Process(ctx, req)
		}
	}
	if err != nil {
		return nil, err
	}

	switch {
	case status != nil:
		return abbotgopb.NewResponse(status)
	default:
		return nil, fmt.Errorf("invalid result")
	}
}

func (m *Manager) handleHostNetworkConfigEnsure(
	ctx context.Context, data []byte,
) (*abbotgopb.HostNetworkStatusResponse, error) {
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

		expectedNames := make(map[string]string)
		for i, exp := range req.Expected {
			name := exp.GetMetadata().GetName()
			if name == "" {
				return fmt.Errorf("must specify interface name")
			}

			expectedNames[name] = name

			existingDev, ok := m.hostDevices[name]
			if !ok {
				add = append(add, req.Expected[i])
				continue

			}

			err = existingDev.EnsureConfig(req.Expected[i])
			if err != nil {
				m.logger.I("failed to ensure config of device", log.Error(err))
				remove = append(remove, name)
				add = append(add, req.Expected[i])
			}
		}

		for name := range m.hostDevices {
			if _, ok := expectedNames[name]; !ok {
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
			for i := range m.hostDeviceNameSeq {
				m.hostDeviceNameSeq = append(m.hostDeviceNameSeq[:i], m.hostDeviceNameSeq[i+1:]...)
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
				d, err2 = driver.NewDriver(m.ctx, constant.DriverBridge, runtime.GOOS, exp)
				if err2 != nil {
					return fmt.Errorf("failed to create bridge interface %s: %w", name, err2)
				}
			case *abbotgopb.HostNetworkInterface_Wireguard:
				d, err2 = driver.NewDriver(m.ctx, constant.DriverWireguard, runtime.GOOS, exp)
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

	return abbotgopb.NewHostNetworkStatusResponse(ifaces...), nil
}

func (m *Manager) checkDeviceStatus() ([]*abbotgopb.HostNetworkInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ret []*abbotgopb.HostNetworkInterface
	for _, name := range m.hostDeviceNameSeq {
		dev, ok := m.hostDevices[name]
		if !ok {
			return nil, fmt.Errorf("inconsistent sequence and device, interface %s not found", name)
		}

		cfg, err := dev.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to check device config: %w", err)
		}

		ret = append(ret, cfg)
	}

	return ret, nil
}
