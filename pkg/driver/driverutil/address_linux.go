package driverutil

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func EnsureAddresses(h *netlink.Handle, link netlink.Link, addresses []string) error {
	expected := make(map[string]*netlink.Addr)
	for _, addr := range addresses {
		a, err := netlink.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("invalid address %s: %w", addr, err)
		}
		expected[a.String()] = a
	}

	actual, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to check link addresses: %w", err)
	}

	var (
		toRemove []*netlink.Addr
	)
	for i, actualAddr := range actual {
		found := false
		for _, expectedAddr := range expected {
			if expectedAddr.Equal(actualAddr) {
				found = true
			}
		}

		if !found {
			toRemove = append(toRemove, &actual[i])
		} else {
			delete(expected, actualAddr.String())
		}
	}

	for _, addr := range toRemove {
		err = h.AddrDel(link, addr)
		if err != nil {
			return fmt.Errorf("failed to remove unwanted address %s: %w", addr.String(), err)
		}
	}

	for _, addr := range expected {
		err = h.AddrAdd(link, addr)
		if err != nil {
			return fmt.Errorf("failed to add address %s: %w", addr.String(), err)
		}
	}

	return nil
}
