package network

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"arhat.dev/pkg/log"
	"go.uber.org/multierr"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

type Manager struct {
	ctx              context.Context
	logger           log.Interface
	hostNetwork      *conf.HostNetworkConfig
	containerNetwork *conf.ContainerNetworkConfig

	hostDevices []types.Driver

	mu *sync.RWMutex
}

func NewManager(
	ctx context.Context,
	hostNetwork *conf.HostNetworkConfig,
	containerNetwork *conf.ContainerNetworkConfig,
) (*Manager, error) {
	return &Manager{
		ctx:              ctx,
		logger:           log.Log,
		hostNetwork:      hostNetwork,
		containerNetwork: containerNetwork,
		mu:               new(sync.RWMutex),
	}, nil
}

func ensureAllDevices(hostDevices []types.Driver) error {
	var err error
	for _, dev := range hostDevices {
		err = multierr.Append(err, dev.Ensure(true))
	}

	return err
}

func (m *Manager) Start() error {
	err := func() error {
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, n := range m.hostNetwork.Interfaces {
			m.logger.D("create driver", log.String("driver", n.Driver))
			d, err := driver.NewDriver(n.Driver, runtime.GOOS, n.Config)
			if err != nil {
				return fmt.Errorf("failed to create driver %s: %w", n.Driver, err)
			}

			m.hostDevices = append(m.hostDevices, d)
		}

		m.logger.D("ensuring all devices for the first time")
		err := ensureAllDevices(m.hostDevices)
		if err != nil {
			return fmt.Errorf("failed to ensure all network device running for the first time: %w", err)
		}
		return nil
	}()
	if err != nil {
		return err
	}

	m.logger.V("all devices ensured")

	go func() {
		m.logger.V("starting all devices ensure routine")
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()

		for {
			select {
			case <-tk.C:
				m.mu.RLock()
				m.logger.D("routine: ensuring all devices")
				err2 := ensureAllDevices(m.hostDevices)
				if err2 != nil {
					m.logger.I("failed to ensure all network device running", log.Error(err2))
				} else {
					m.logger.D("routine: all devices ensured")
				}
				m.mu.RUnlock()
			case <-m.ctx.Done():
				return
			}
		}
	}()

	select {
	case <-m.ctx.Done():
		return nil
	}
}
