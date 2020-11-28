package host

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/iohelper"
	"arhat.dev/pkg/log"

	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/drivers"
)

func (m *Manager) updateInterface(
	config *abbotgopb.HostNetworkInterface,
) (
	prevConfig *abbotgopb.HostNetworkInterface,
	err error,
) {
	configData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new config data: %w", err)
	}

	name := config.Metadata.Name
	existingDev, ok := m.hostDevices[name]
	if !ok {
		return nil, fmt.Errorf("unexpected interface %q not found", name)
	}

	index := -1
	for i, currentName := range m.hostDeviceNameSeq {
		if currentName == name {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("unexpected interface %q index not found", name)
	}

	prevConfig, err = existingDev.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get old config of interface %q: %w", name, err)
	}

	prevConfigData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal previous config data: %w", err)
	}

	filename := m.formatConfigFilename(index, name)
	err = ioutil.WriteFile(filename, configData, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to update config data: %w", err)
	}

	defer func() {
		if err == nil {
			return
		}

		err2 := ioutil.WriteFile(filename, prevConfigData, 0640)
		if err2 != nil {
			m.logger.I("failed to restore interface old config", log.Error(err2))
		}
	}()

	m.logger.I("updating running interface", log.String("name", name))
	err = existingDev.EnsureConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure config of interface %q: %w", name, err)
	}

	return prevConfig, nil
}

func (m *Manager) deleteInterface(name string) (config *abbotgopb.HostNetworkInterface, err error) {
	existingDev, ok := m.hostDevices[name]
	if !ok {
		return nil, fmt.Errorf("unexpected interface %q not found", name)
	}

	index := -1
	for i, currentName := range m.hostDeviceNameSeq {
		if currentName == name {
			index = i
			break
		}
	}

	if index == -1 {
		return nil, fmt.Errorf("unexpected interface %q index not found", name)
	}

	config, err = existingDev.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get config of interface %q: %w", name, err)
	}

	configData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}

	// remove config data
	filename := m.formatConfigFilename(index, name)
	err = os.Remove(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to remove config data: %w", err)
	}

	defer func() {
		if err == nil {
			return
		}

		// restore config on error
		_, err2 := iohelper.WriteFile(filename, configData, 0640, false)
		if err2 != nil {
			m.logger.I("failed to restore config data", log.Error(err2))
		}
	}()

	m.logger.I("deleting running interface", log.String("name", name))
	err = existingDev.Delete(true)
	if err != nil {
		return nil, fmt.Errorf("failed to delete existing interface: %w", err)
	}

	// update sequence and index

	m.hostDeviceNameSeq = append(m.hostDeviceNameSeq[:index], m.hostDeviceNameSeq[index+1:]...)
	delete(m.hostDevices, name)

	return config, nil
}

func (m *Manager) addInterface(config *abbotgopb.HostNetworkInterface) (_ string, err error) {
	configData, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config data: %w", err)
	}

	var d drivers.Interface
	switch config.Config.(type) {
	case *abbotgopb.HostNetworkInterface_Bridge:
		d, err = drivers.NewDriver(m.ctx, config.Provider, constant.DriverBridge, config)
	case *abbotgopb.HostNetworkInterface_Wireguard:
		d, err = drivers.NewDriver(m.ctx, config.Provider, constant.DriverWireguard, config)
	default:
		return "", fmt.Errorf("unknown driver config for interface %s", config.Metadata.Name)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create interface %s: %w", config.Metadata.Name, err)
	}

	filename := m.formatConfigFilename(len(m.hostDeviceNameSeq), config.Metadata.Name)
	undoConfigWrite, err := iohelper.WriteFile(filename, configData, 0640, false)
	if err != nil {
		return "", fmt.Errorf("failed to persist config before interface creation: %w", err)
	}

	defer func() {
		if err == nil {
			return
		}

		err2 := d.Delete(true)
		if err2 != nil {
			m.logger.I("failed to delete failed interface", log.String("name", d.Name()), log.Error(err2))
		}

		// undoConfigWrite config write on error with best effort
		err2 = undoConfigWrite()
		if err2 != nil {
			m.logger.I("failed to undo config data write", log.Error(err2))
		}
	}()

	// created interface, bring it up for the first to validate config
	err = d.Ensure(true)
	if err != nil {
		return "", fmt.Errorf("failed to bring interface %q up: %w", config.Metadata.Name, err)
	}

	name := d.Name()

	if name != config.Metadata.Name {
		// name updated after start
		err = os.Rename(filename, m.formatConfigFilename(len(m.hostDeviceNameSeq), name))
		if err != nil {
			return "", fmt.Errorf("failed to update config file name: %w", err)
		}
	}

	m.hostDeviceNameSeq = append(m.hostDeviceNameSeq, name)
	m.hostDevices[name] = d

	return name, nil
}

func (m *Manager) formatConfigFilename(index int, name string) string {
	return filepath.Join(
		m.dataDir,
		fmt.Sprintf("%s.%s.json", strconv.FormatInt(int64(index), 10), name),
	)
}
