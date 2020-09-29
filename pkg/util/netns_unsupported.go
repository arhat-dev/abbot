// +build !linux

package util

import "fmt"

func DoWithNetworkNamespace(pid string, do func() error) error {
	return fmt.Errorf("operation not supported")
}
