// +build !windows

package netlink

import (
	"github.com/vishvananda/netlink"
)

// nolint:golint
const (
	FAMILY_ALL = netlink.FAMILY_ALL
	SCOPE_LINK = netlink.SCOPE_LINK
)
