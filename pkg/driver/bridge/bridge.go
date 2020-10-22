package bridge

import (
	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/driver"
)

func init() {
	driver.Register(constant.DriverBridge, "linux", NewDriver, NewConfig)
}

func (d *Driver) Provider() string {
	return d.provider
}

func (d *Driver) DriverName() string {
	return constant.DriverBridge
}
