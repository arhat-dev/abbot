package network

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"text/template"
	"time"

	"arhat.dev/pkg/log"
	"github.com/containernetworking/cni/libcni"
	"go.uber.org/multierr"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

type Manager struct {
	ctx    context.Context
	logger log.Interface

	hostDeviceNameSeq []string
	hostDevices       map[string]types.Driver
	hostMU            *sync.RWMutex

	containerDev      string
	cniDataDir        string
	cniConfigFile     string
	cniLookupPaths    []string
	cniConfigTemplate *template.Template
	cniMU             *sync.RWMutex

	cniLoopbackConfig     *libcni.NetworkConfigList
	cniNetworkConfigBytes []byte
	cniNetworkConfig      *libcni.NetworkConfigList
}

func NewManager(
	ctx context.Context,
	hostNetwork *conf.HostNetworkConfig,
	containerNetwork *conf.ContainerNetworkConfig,
) (*Manager, error) {

	var nameSeq []string
	hostDevices := make(map[string]types.Driver)
	for _, n := range hostNetwork.Interfaces {
		if _, ok := hostDevices[n.Name]; ok {
			return nil, fmt.Errorf("invalid duplicate interface name %s", n.Name)
		}

		d, err := driver.NewDriver(ctx, n.Driver, runtime.GOOS, n.Name, n.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create driver %s for %s: %w", n.Driver, n.Name, err)
		}

		hostDevices[n.Name] = d
		nameSeq = append(nameSeq, n.Name)
	}

	tmpl, err := template.New("").Parse(containerNetwork.Template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cni config template: %w", err)
	}

	cndDataDir, err := filepath.Abs(containerNetwork.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path of container network data dir: %w", err)
	}

	cniConfigFile := filepath.Join(cndDataDir, "config.json")

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
		logger: log.Log,

		hostDeviceNameSeq: nameSeq,
		hostDevices:       hostDevices,
		hostMU:            new(sync.RWMutex),

		containerDev:      containerNetwork.ContainerInterfaceName,
		cniDataDir:        cndDataDir,
		cniConfigFile:     cniConfigFile,
		cniLookupPaths:    containerNetwork.CNIPluginsLookupPaths,
		cniConfigTemplate: tmpl,
		cniMU:             new(sync.RWMutex),

		cniLoopbackConfig:     loopbackConfig,
		cniNetworkConfigBytes: cniNetworkConfigBytes,
		cniNetworkConfig:      cniNetworkConfig,
	}, nil
}

func (m *Manager) Start() error {
	var err error
	err = func() error {
		m.hostMU.Lock()
		defer m.hostMU.Unlock()

		m.logger.D("ensuring all host interfaces for the first time")
		m.hostDeviceNameSeq, err = ensureAllDevices(m.hostDeviceNameSeq, m.hostDevices)
		if err != nil {
			return fmt.Errorf("failed to ensure all host interfaces running for the first time: %w", err)
		}

		return nil
	}()
	if err != nil {
		return err
	}

	m.logger.V("all host interfaces ensured")
	m.logger.D("starting host interfaces ensure routine")
	go m.ensureHostInterfacesPeriodically(5 * time.Second)

	// nolint:gosimple
	select {
	case <-m.ctx.Done():
	}

	m.hostMU.Lock()
	defer m.hostMU.Unlock()
	for i := len(m.hostDeviceNameSeq) - 1; i >= 0; i-- {
		name := m.hostDeviceNameSeq[i]
		dev, ok := m.hostDevices[name]
		if !ok {
			continue
		}

		err = dev.Delete()
		if err != nil {
			m.logger.I("failed to delete device", log.String("ifname", name), log.Error(err))
		}
	}

	return nil
}

func (m *Manager) ensureHostInterfacesPeriodically(interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()

	for {
		select {
		case <-tk.C:
			m.hostMU.RLock()
			m.logger.V("routine: ensuring all host interfaces")
			_, err := ensureAllDevices(m.hostDeviceNameSeq, m.hostDevices)
			if err != nil {
				m.logger.I("failed to ensure all host interfaces running", log.Error(err))
			} else {
				m.logger.V("routine: all host interfaces running")
			}
			m.hostMU.RUnlock()
		case <-m.ctx.Done():
			return
		}
	}
}

func ensureAllDevices(devSeq []string, hostDevices map[string]types.Driver) ([]string, error) {
	var (
		newSeq []string
		err    error
	)
	for _, devName := range devSeq {
		dev, ok := hostDevices[devName]
		if !ok {
			continue
		}

		err2 := dev.Ensure(true)
		if err2 != nil {
			err = multierr.Append(err, fmt.Errorf("failed to ensure driver for %s: %w", devName, err2))
		}

		newSeq = append(newSeq, dev.Name())
	}

	return newSeq, err
}
