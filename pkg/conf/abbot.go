/*
Copyright 2019 The arhat.dev Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conf

import (
	"encoding/json"
	"fmt"
	"runtime"

	"arhat.dev/pkg/log"
	"gopkg.in/yaml.v2"

	"arhat.dev/abbot/pkg/driver"
)

type AbbotConfig struct {
	Abbot            AppConfig              `json:"abbot" yaml:"abbot"`
	HostNetwork      HostNetworkConfig      `json:"hostNetwork" yaml:"hostNetwork"`
	ContainerNetwork ContainerNetworkConfig `json:"containerNetwork" yaml:"containerNetwork"`
}

type AppConfig struct {
	Log    log.ConfigSet `json:"log" yaml:"log"`
	Listen string        `json:"listen" yaml:"listen"`
}

type InterfaceConfig struct {
	Driver string      `json:"driver" yaml:"driver"`
	Config interface{} `json:"config" yaml:"config"`
}

func (c *InterfaceConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	c.Driver, c.Config, err = unmarshalInterfaceConfig(m)
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

	c.Driver, c.Config, err = unmarshalInterfaceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func unmarshalInterfaceConfig(m map[string]interface{}) (driverName string, config interface{}, err error) {
	n, ok := m["driver"]
	if !ok {
		err = fmt.Errorf("must specify driver name")
		return
	}

	driverName, ok = n.(string)
	if !ok {
		err = fmt.Errorf("driver name must be a string")
		return
	}

	config, err = driver.NewConfig(driverName, runtime.GOOS)
	if err != nil {
		return driverName, nil, nil
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

	return driverName, config, nil
}
