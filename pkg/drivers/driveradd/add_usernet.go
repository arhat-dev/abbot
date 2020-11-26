// +build !nousernet
// +build !plan9,!386,!arm,!mips,!mipsle

package driveradd

import (
	// Add usernet support
	_ "arhat.dev/abbot/pkg/drivers/usernet"
)
