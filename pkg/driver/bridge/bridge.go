package bridge

import (
	"arhat.dev/abbot-proto/abbotgopb"

	"arhat.dev/abbot/pkg/driver"
)

func init() {
	driver.Register("bridge", "linux", NewDriver, NewConfig)
}

func NewConfig() interface{} {
	return &Config{
		NetworkInterface: abbotgopb.NetworkInterface{
			Name:            "",
			Mtu:             1440,
			HardwareAddress: "",
			Addresses:       nil,
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
