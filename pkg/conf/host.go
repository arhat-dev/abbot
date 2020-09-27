package conf

import (
	"arhat.dev/abbot/pkg/driver"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"runtime"
)

type InterfaceConfig struct {
	Name   string `json:"name" yaml:"name"`
	Driver string `json:"driver" yaml:"driver"`

	Config interface{} `json:"config" yaml:"config"`
}

func (c *InterfaceConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	c.Name, c.Driver, c.Config, err = unmarshalInterfaceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func (c *InterfaceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	m := make(map[string]interface{})

	err := unmarshal(&m)
	if err != nil {
		return err
	}

	c.Name, c.Driver, c.Config, err = unmarshalInterfaceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func unmarshalInterfaceConfig(m map[string]interface{}) (name, driverName string, config interface{}, err error) {
	n, ok := m["name"]
	if !ok {
		err = fmt.Errorf("must specify interface name")
		return
	}

	name, ok = n.(string)
	if !ok {
		err = fmt.Errorf("device name must be a string")
		return
	}

	d, ok := m["driver"]
	if !ok {
		err = fmt.Errorf("must specify driver name")
		return
	}

	driverName, ok = d.(string)
	if !ok {
		err = fmt.Errorf("driver name must be a string")
		return
	}

	config, err = driver.NewConfig(driverName, runtime.GOOS)
	if err != nil {
		return name, driverName, nil, nil
	}

	configRaw, ok := m["config"]
	if !ok {
		err = fmt.Errorf("must provide driver config")
		return
	}

	var configData []byte
	switch d := configRaw.(type) {
	case []byte:
		configData = d
	case string:
		configData = []byte(d)
	default:
		configData, err = yaml.Marshal(d)
		if err != nil {
			err = fmt.Errorf("failed to get driver config bytes: %w", err)
			return
		}
	}

	err = yaml.UnmarshalStrict(configData, config)
	if err != nil {
		return
	}

	return name, driverName, config, nil
}

type HostNetworkConfig struct {
	Interfaces []InterfaceConfig `json:"interfaces" yaml:"interfaces"`
	// Proxies config to redirect network traffic
	Proxies []ProxyConfig `json:"proxies" yaml:"proxies"`
}
