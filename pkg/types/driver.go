package types

import "arhat.dev/abbot-proto/abbotgopb"

type Driver interface {
	// Provider of the interface, `static` means from config file
	Provider() string

	// DriverName of the interface
	DriverName() string

	// Name of the interface
	Name() string

	// Ensure up/down state of this interface
	Ensure(up bool) error

	// EnsureConfig ensure config is up to date
	EnsureConfig(config *abbotgopb.HostNetworkInterface) error

	// GetConfig retrieve config of the interface
	GetConfig() (*abbotgopb.HostNetworkInterface, error)

	// Delete this interface
	Delete() error
}
