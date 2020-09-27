package types

type Driver interface {
	// Name of the interface
	Name() string

	// Ensure up/down state of this interface
	Ensure(up bool) error

	// Delete this interface
	Delete() error
}
