package host

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"arhat.dev/pkg/log"
	"go.uber.org/multierr"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/container"
	"arhat.dev/abbot/pkg/drivers"
)

type Manager struct {
	ctx    context.Context
	logger log.Interface

	dataDir string

	hostDeviceNameSeq []string
	hostDevices       map[string]drivers.Interface
	mu                *sync.RWMutex

	containerMgr *container.Manager
}

func NewManager(
	ctx context.Context,
	config *conf.HostNetworkConfig,
	containerMgr *container.Manager,
) (*Manager, error) {
	var nameSeq []string
	hostDevices := make(map[string]drivers.Interface)
	for _, n := range config.Interfaces {
		d, err := drivers.NewDriver(ctx, constant.ProviderStatic, n.Driver, n.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create driver %s: %w", n.Driver, err)
		}

		name := d.Name()
		if _, ok := hostDevices[name]; ok {
			return nil, fmt.Errorf("invalid duplicate interface name %s", name)
		}

		hostDevices[name] = d
		nameSeq = append(nameSeq, name)
	}

	return &Manager{
		ctx:    ctx,
		logger: log.Log,

		dataDir: config.DataDir,

		hostDeviceNameSeq: nameSeq,
		hostDevices:       hostDevices,
		mu:                new(sync.RWMutex),

		containerMgr: containerMgr,
	}, nil
}

func (m *Manager) Start() error {
	var err error
	err = func() error {
		m.logger.D("ensuring all host interfaces for the first time")
		err = m.ensureAllDevices()
		if err != nil {
			return fmt.Errorf("failed to ensure all host interfaces running for the first time: %w", err)
		}

		return nil
	}()
	if err != nil {
		return err
	}

	m.logger.V("all host interfaces ensured")

	// use defer to make sure cleanup will always run
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		// delete interfaces in reversed order
		for i := len(m.hostDeviceNameSeq) - 1; i >= 0; i-- {
			name := m.hostDeviceNameSeq[i]
			dev, ok := m.hostDevices[name]
			if !ok {
				continue
			}

			err = dev.Delete(false)
			if err != nil {
				m.logger.I("failed to delete device", log.String("ifname", name), log.Error(err))
			}
		}
	}()

	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()

	m.logger.D("running host interfaces ensure routine")
	for {
		select {
		case <-tk.C:
			m.logger.V("routine: ensuring all host interfaces")
			err := m.ensureAllDevices()
			if err != nil {
				m.logger.I("routine: not all host interfaces running", log.Error(err))
			} else {
				m.logger.V("routine: all host interfaces running")
			}
		case <-m.ctx.Done():
			return nil
		}
	}
}

func (m *Manager) ensureAllDevices() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var (
		newSeq []string
		err    error
	)
	for i, oldName := range m.hostDeviceNameSeq {
		dev, ok := m.hostDevices[oldName]
		if !ok {
			err = multierr.Append(err, fmt.Errorf("unexpected unknown interface %q", oldName))
			continue
		}

		err2 := dev.Ensure(true)
		if err2 != nil {
			err = multierr.Append(err, fmt.Errorf("failed to ensure interface %q: %w", oldName, err2))
		}

		realName := dev.Name()
		filename := m.formatConfigFilename(i, realName)
		if realName != oldName {
			// name updated, update config data accordingly
			oldFile := m.formatConfigFilename(i, oldName)
			err2 = os.Rename(oldFile, filename)
			if err2 != nil {
				err = multierr.Append(err,
					fmt.Errorf("failed to update config file from %q to %q: %w", oldFile, filename, err2),
				)
			}
		}

		newSeq = append(newSeq, dev.Name())
	}

	m.hostDeviceNameSeq = newSeq

	return err
}
