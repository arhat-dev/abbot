package bridge

import (
	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/drivers"
)

func init() {
	drivers.Register(constant.DriverBridge, NewDriver, NewConfig)
}

func (d *Driver) Provider() string {
	return d.provider
}

func (d *Driver) DriverName() string {
	return constant.DriverBridge
}
