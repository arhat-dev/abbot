package conf

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"arhat.dev/abbot/pkg/drivers"
)

type HostNetworkConfig struct {
	// DataDir to store host network config
	DataDir string `json:"dataDir" yaml:"dataDir"`

	// Interfaces are static interface definitions, their provider will be set
	// to `static`
	Interfaces []InterfaceConfig `json:"interfaces" yaml:"interfaces"`

	// Proxies config to redirect network traffic
	Proxies []ProxyConfig `json:"proxies" yaml:"proxies"`
}

type InterfaceConfig struct {
	// Driver the name of the driver backend
	Driver string `json:"driver" yaml:"driver"`

	// Config of this interface, options are driver dependent
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
