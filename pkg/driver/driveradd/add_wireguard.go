// +build !nowireguard
// +build freebsd linux darwin windows,386 windows,amd64 openbsd,amd64

package driveradd

import (
	// Add wireguard support
	_ "arhat.dev/abbot/pkg/driver/wireguard"
)
