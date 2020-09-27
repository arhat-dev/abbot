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

	h := &netlink.Handle{}
	link, err := h.LinkByName(d.name)
	if err != nil {
		// TODO: log err
		_ = err

		return
	}

	if up {
		_ = h.LinkSetUp(link)
		d.dev.Up()
	} else {
		_ = h.LinkSetDown(link)
		d.dev.Down()
	}
}

func ensureAddresses(ifname string, addresses map[string]*netlink.Addr) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	return util.EnsureIPs(&netlink.Handle{}, link, addresses)
}

func ensureRoute(ifname string, table int, ipRanges map[string]*net.IPNet) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	return util.EnsureRoutes(&netlink.Handle{}, link, table, ipRanges)
}
