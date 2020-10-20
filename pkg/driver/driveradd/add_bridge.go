// +build !nobridge
// +build linux

package driveradd

import (
	// Add bridge support
	_ "arhat.dev/abbot/pkg/driver/bridge"
)
