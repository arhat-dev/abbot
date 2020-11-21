package conf

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"arhat.dev/abbot/pkg/driver"
)

type DriverConfig interface{}

type InterfaceConfig struct {
	Driver string `json:"-" yaml:"-"`
	Name   string `json:"-" yaml:"-"`

	DriverConfig `json:",inline" yaml:",inline"`
}

func (c *InterfaceConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	c.Driver, c.Name, c.DriverConfig, err = unmarshalInterfaceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func (c *InterfaceConfig) UnmarshalYAML(value *yaml.Node) error {
	m := make(map[string]interface{})

	configData, err := yaml.Marshal(value)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(configData, &m)
	if err != nil {
		return err
	}

	c.Driver, c.Name, c.DriverConfig, err = unmarshalInterfaceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func unmarshalInterfaceConfig(m map[string]interface{}) (driverName, ifname string, _ interface{}, _ error) {
	d, ok := m["driver"]
	if !ok {
		return "", "", nil, fmt.Errorf("must specify driver type")
	}

	driverName, ok = d.(string)
	if !ok {
		return "", "", nil, fmt.Errorf("driver type must be a string")
	}

	n, ok := m["name"]
	if !ok {
		return "", "", nil, fmt.Errorf("must specify interface name")
	}

	ifname, ok = n.(string)
	if !ok || ifname == "" {
		return "", "", nil, fmt.Errorf("invalid interface name: %s", ifname)
	}

	delete(m, "driver")

	configData, err := json.Marshal(m)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get driver config bytes: %w", err)
	}

	config, err := driver.NewConfig(driverName)
	if err != nil {
		return "", "", nil, fmt.Errorf("unknown driver %s: %w", driverName, err)
	}

	dec := json.NewDecoder(bytes.NewReader(configData))
	dec.DisallowUnknownFields()
	err = dec.Decode(config)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to resolve driver config %s: %w", driverName, err)
	}

	return driverName, ifname, config, nil
}

type HostNetworkConfig struct {
	Interfaces []InterfaceConfig `json:"interfaces" yaml:"interfaces"`
	// Proxies config to redirect network traffic
	Proxies []ProxyConfig `json:"proxies" yaml:"proxies"`
}
