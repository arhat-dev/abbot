package bridge

import (
	"fmt"

	"arhat.dev/abbot-proto/abbotgopb"
)

func NewConfig() interface{} {
	return &Config{
		NetworkInterface: abbotgopb.NetworkInterface{
			Name:            "",
			Mtu:             1440,
			HardwareAddress: "",
			Addresses:       nil,
			DeleteOnExit:    false,
		},
		DriverBridge: abbotgopb.DriverBridge{
			Alias:      "",
			TxQueueLen: 0,
			Promisc:    false,

			Hairpin:      false,
			Guard:        false,
			FastLeave:    false,
			RootBlock:    false,
			Learning:     false,
			Flood:        false,
			ProxyArp:     false,
			ProxyArpWifi: false,
		},
	}
}

type Config struct {
	abbotgopb.NetworkInterface `json:",inline" yaml:",inline"`
	abbotgopb.DriverBridge     `json:",inline" yaml:",inline"`
}

func (c *Config) castToHostNetworkInterface(name string) (*abbotgopb.HostNetworkInterface, error) {
	metadataBytes, err := c.NetworkInterface.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal network metadata: %w", err)
	}

	configBytes, err := c.DriverBridge.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bridge config: %w", err)
	}

	md := new(abbotgopb.NetworkInterface)
	_ = md.Unmarshal(metadataBytes)
	cfg := new(abbotgopb.DriverBridge)
	_ = cfg.Unmarshal(configBytes)

	md.Name = name

	return &abbotgopb.HostNetworkInterface{
		Metadata: md,
		Config:   &abbotgopb.HostNetworkInterface_Bridge{Bridge: cfg},
	}, nil
}
