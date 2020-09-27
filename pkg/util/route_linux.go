package util

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func EnsureRoutes(h *netlink.Handle, link netlink.Link, table int, ipRanges map[string]*net.IPNet) error {
	attr := link.Attrs()
	ifname := attr.Name

	routes, err := h.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to check route for device %s: %w", ifname, err)
	}

	var (
		actual       = make(map[string]*net.IPNet)
		actualRoutes = make(map[string]*netlink.Route)
	)
	for i, r := range routes {
		if r.Dst == nil {
			err = h.RouteDel(&routes[i])
			if err != nil {
				return fmt.Errorf("failed to delete empty route: %w", err)
			}
			continue
		}

		dst := r.Dst.String()
		actual[dst], err = netlink.ParseIPNet(dst)
		if err != nil {
			return fmt.Errorf("unexpected dest ip net %s: %w", dst, err)
		}

		actualRoutes[dst] = &routes[i]
	}

	toAdd, toDel := GetIPNetsToAddAndToDelete(actual, ipRanges)

	for k := range toDel {
		err = h.RouteDel(actualRoutes[k])
		if err != nil {
			return fmt.Errorf("failed to remove route for device %s: %w", ifname, err)
		}
	}

	for k, r := range toAdd {
		err = h.RouteAdd(&netlink.Route{
			LinkIndex: attr.Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       r,
			Priority:  0,
			Table:     table,
		})
		if err != nil {
			return fmt.Errorf("failed to add route for device %s to dest %s: %w", ifname, k, err)
		}
	}

	return nil
}
