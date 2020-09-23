package types

type Driver interface {
	Ensure(up bool) error
	Delete() error
}
