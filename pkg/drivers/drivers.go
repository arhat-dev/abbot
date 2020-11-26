package drivers

import (
	"context"
	"fmt"

	"arhat.dev/abbot/pkg/types"
)

type key struct {
	name string
}

type factory struct {
	newDriver FactoryFunc
	newConfig ConfigFactoryFunc
}

type (
	FactoryFunc       func(ctx context.Context, provider string, cfg interface{}) (types.Driver, error)
	ConfigFactoryFunc func() interface{}
)

var supportedDrivers = make(map[key]factory)

func Register(name string, newDriver FactoryFunc, newDriverConfig ConfigFactoryFunc) {
	supportedDrivers[key{
		name: name,
	}] = factory{
		newDriver: newDriver,
		newConfig: newDriverConfig,
	}
}

func NewDriver(ctx context.Context, provider, driverName string, cfg interface{}) (types.Driver, error) {
	f, ok := supportedDrivers[key{
		name: driverName,
	}]
	if !ok {
		return nil, fmt.Errorf("driver %s not found", driverName)
	}

	return f.newDriver(ctx, provider, cfg)
}

func NewConfig(name string) (interface{}, error) {
	f, ok := supportedDrivers[key{
		name: name,
	}]
	if !ok {
		return nil, fmt.Errorf("driver config for %s not found", name)
	}

	return f.newConfig(), nil
}
