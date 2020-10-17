package usernet

import (
	"context"
	"fmt"

	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	DriverName = "usernet"
)

func init() {
	driver.Register(DriverName, "aix", NewDriver, NewConfig)
	driver.Register(DriverName, "dragonfly", NewDriver, NewConfig)
	driver.Register(DriverName, "darwin", NewDriver, NewConfig)
	driver.Register(DriverName, "freebsd", NewDriver, NewConfig)
	driver.Register(DriverName, "openbsd", NewDriver, NewConfig)
	driver.Register(DriverName, "solaris", NewDriver, NewConfig)
	driver.Register(DriverName, "netbsd", NewDriver, NewConfig)
	driver.Register(DriverName, "windows", NewDriver, NewConfig)
	driver.Register(DriverName, "linux", NewDriver, NewConfig)
}

func NewDriver(ctx context.Context, name string, cfg interface{}) (types.Driver, error) {
	return nil, fmt.Errorf("driver usernet unimplemented")
}

type Driver struct {
	name     string
	netStack *stack.Stack
}

// Name of the interface
func (d *Driver) Name() string {
	return d.name
}

// Ensure up/down state of this interface
func (d *Driver) Ensure(up bool) error {
	_ = d.netStack
	return fmt.Errorf("driver usernet unimplemented")
}

// Delete this interface
func (d *Driver) Delete() error {
	return fmt.Errorf("driver usernet unimplemented")
}
