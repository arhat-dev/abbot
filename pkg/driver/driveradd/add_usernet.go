// +build !nousernet
// +build !plan9

package driveradd

import (
	// Add usernet support
	_ "arhat.dev/abbot/pkg/driver/usernet"
)
