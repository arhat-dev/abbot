package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"arhat.dev/abbot-proto/abbotgopb"
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
	m.logger.D("loading dynamic interfaces")

	// load interfaces with non static provider
	files, err := ioutil.ReadDir(m.dataDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to check data dir: %w", err)
		}

		err = os.MkdirAll(m.dataDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create data dir: %w", err)
		}
	}

	type ifnameAndIndex struct {
		index      int64
		filename   string
		configData []byte
		config     *abbotgopb.HostNetworkInterface
	}

	var dynamicIfaces []ifnameAndIndex
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		filename := f.Name()
		if filepath.Ext(filename) != ".json" {
			// ignore non .json file
			continue
		}

		ifaceIndexAndName := strings.TrimSuffix(filepath.Base(filename), ".json")
		parts := strings.SplitN(ifaceIndexAndName, ".", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid config file name %q", filename)
		}

		oldIdx, err2 := strconv.ParseInt(parts[0], 10, 64)
		if err2 != nil {
			return fmt.Errorf("unexpected interface index: %w", err2)
		}

		if oldIdx < 0 {
			return fmt.Errorf("unexpected negative interface index")
		}

		ifname := parts[1]

		configData, err2 := ioutil.ReadFile(filename)
		if err2 != nil {
			return fmt.Errorf("failed to load interface config data: %w", err2)
		}

		config := new(abbotgopb.HostNetworkInterface)
		err2 = json.Unmarshal(configData, config)
		if err2 != nil {
			return fmt.Errorf("failed to unmarshal interface config data: %w", err2)
		}

		switch config.Provider {
		case constant.ProviderStatic:
			// static config is not persisted
			return fmt.Errorf("unexpected static config %q", filename)
		case "":
			return fmt.Errorf("invalid interface config with empty provider %q", filename)
		default:
			// load this dynamic interface
		}

		if ifname != config.GetMetadata().GetName() {
			return fmt.Errorf(
				"unexpected inconsistent interface name, want %q, actual %q",
				ifname, config.GetMetadata().GetName(),
			)
		}

		dynamicIfaces = append(dynamicIfaces, ifnameAndIndex{
			index:      oldIdx,
			filename:   filename,
			configData: configData,
			config:     config,
		})
	}

	// ensure interface order
	sort.SliceStable(dynamicIfaces, func(i, j int) bool {
		return dynamicIfaces[i].index < dynamicIfaces[j].index
	})

	m.logger.D("resolved dynamic interfaces, creating")
	for _, iface := range dynamicIfaces {
		err = os.Remove(iface.filename)
		if err != nil {
			return fmt.Errorf("failed to remove old interface config: %w", err)
		}

		_, err = m.addInterface(iface.config)
		if err != nil {
			err2 := ioutil.WriteFile(iface.filename, iface.configData, 0640)
			if err2 != nil {
				err2 = fmt.Errorf("failed to restore interface config: %w", err2)
			}

			return multierr.Append(
				fmt.Errorf("failed to add persisted interface: %w", err),
				err2,
			)
		}
	}

	m.logger.D("ensuring all host interfaces for the first time")
	err = m.ensureAllDevices()
	if err != nil {
		return fmt.Errorf("failed to ensure all host interfaces running for the first time: %w", err)
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
