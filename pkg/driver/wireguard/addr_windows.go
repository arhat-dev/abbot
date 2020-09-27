package wireguard

import (
	"net"

	"github.com/vishvananda/netlink"

	"arhat.dev/abbot/pkg/util"
)

func (d *Driver) ensureUp(up bool) {
	if d.dev == nil {
		return
	}

	if up {
		d.dev.Up()
	} else {
		d.dev.Down()
	}
}

func ensureAddresses(ifname string, addresses map[string]*netlink.Addr) error {
	return util.EnsureIPs(ifname, addresses)
}

func ensureRoute(ifname string, table int, ipRanges map[string]*net.IPNet) error {
	_ = table
	return util.EnsureRoutes(ifname, ipRanges)
}
