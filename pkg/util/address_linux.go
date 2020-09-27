package util

import (
	"fmt"

	"arhat.dev/abbot/pkg/wrap/netlink"
)

func EnsureIPs(h *netlink.Handle, link netlink.Link, ipAddresses map[string]*netlink.Addr) error {
	ifname := link.Attrs().Name
	actual, err := GetInterfaceIPs(ifname)
	if err != nil {
		return fmt.Errorf("failed to check ip addresses of device %s: %w", ifname, err)
	}

	toAdd, toDel := GetIPsToAddAndToDelete(actual, ipAddresses)
	for _, addr := range toDel {
		err = h.AddrDel(link, addr)
		if err != nil {
			return fmt.Errorf("failed to remove unwanted address %s: %w", addr.String(), err)
		}
	}

	for _, addr := range toAdd {
		err = h.AddrAdd(link, addr)
		if err != nil {
			return fmt.Errorf("failed to add address %s: %w", addr.String(), err)
		}
	}

	return nil
}
