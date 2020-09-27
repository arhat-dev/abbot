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

const (
	OperUp   = netlink.OperUp
	OperDown = netlink.OperDown
)

type (
	Addr              = netlink.Addr
	Handle            = netlink.Handle
	Link              = netlink.Link
	LinkAttrs         = netlink.LinkAttrs
	Route             = netlink.Route
	Protinfo          = netlink.Protinfo
	Bridge            = netlink.Bridge
	LinkNotFoundError = netlink.LinkNotFoundError
)

// functions
var (
	LinkByName   = netlink.LinkByName
	NewLinkAttrs = netlink.NewLinkAttrs
	ParseAddr    = netlink.ParseAddr
	ParseIPNet   = netlink.ParseIPNet
)
