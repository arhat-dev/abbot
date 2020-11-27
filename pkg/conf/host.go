package conf

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"arhat.dev/abbot/pkg/drivers"
)

type InterfaceConfig struct {
	Driver string `json:"driver" yaml:"driver"`
	Name   string `json:"name" yaml:"name"`

	Config interface{} `json:"config" yaml:"config"`
}

func (c *InterfaceConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	return unmarshalInterfaceConfig(m, c)
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

	return unmarshalInterfaceConfig(m, c)
}

func unmarshalInterfaceConfig(m map[string]interface{}, config *InterfaceConfig) error {
	d, ok := m["driver"]
	if !ok {
		return fmt.Errorf("must specify driver type")
	}

	config.Driver, ok = d.(string)
	if !ok {
		return fmt.Errorf("driver type must be a string")
	}

	n, ok := m["name"]
	if !ok {
		return fmt.Errorf("must specify interface name")
	}

	config.Name, ok = n.(string)
	if !ok || config.Name == "" {
		return fmt.Errorf("invalid interface name: %s", config.Name)
	}

	delete(m, "driver")

	configData, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to get driver config bytes: %w", err)
	}

	config.Config, err = drivers.NewConfig(config.Driver)
	if err != nil {
		return fmt.Errorf("unknown driver %s: %w", config.Driver, err)
	}

	dec := json.NewDecoder(bytes.NewReader(configData))
	dec.DisallowUnknownFields()
	err = dec.Decode(config.Config)
	if err != nil {
		return fmt.Errorf("failed to resolve driver config %s: %w", config.Driver, err)
	}

	return nil
}

type HostNetworkConfig struct {
	// Interfaces static interface definitions
	Interfaces []InterfaceConfig `json:"interfaces" yaml:"interfaces"`
	// Proxies config to redirect network traffic
	Proxies []ProxyConfig `json:"proxies" yaml:"proxies"`
}
