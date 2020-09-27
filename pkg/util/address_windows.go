package util

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func EnsureIPs(ifname string, ipAddresses map[string]*netlink.Addr) error {
	ipv4, ipv6, err := getInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to find device %s: %w", ifname, err)
	}

	actualIPs, err := GetInterfaceIPs(ifname)
	if err != nil {
		return fmt.Errorf("failed to check ip addresses of the device %s: %w", ifname, err)
	}

	toAdd, toDel := GetIPsToAddAndToDelete(actualIPs, ipAddresses)
	for _, del := range toDel {
		if del.IP.To4() == nil {
			err = delIP(ipv6, del)
			if err != nil {
				return fmt.Errorf("failed to del ipv6 address %s from device %s", del.String(), err)
			}
		} else {
			err = delIP(ipv4, del)
			if err != nil {
				return fmt.Errorf("failed to del ipv4 address %s from device %s", del.String(), err)
			}
		}
	}

	for _, add := range toAdd {
		if add.IP.To4() == nil {
			err = addIP(ipv6, add)
			if err != nil {
				return fmt.Errorf("failed to add ipv6 address %s to device %s", add.String(), err)
			}
		} else {
			err = addIP(ipv4, add)
			if err != nil {
				return fmt.Errorf("failed to add ipv4 address %s to device %s", add.String(), err)
			}
		}
	}

	return nil
}

func addIP(iface *winipcfg.MibIPInterfaceRow, ip *netlink.Addr) error {
	if iface == nil {
		return nil
	}

	return iface.InterfaceLUID.AddIPAddress(*ip.IPNet)
}

func delIP(iface *winipcfg.MibIPInterfaceRow, ip *netlink.Addr) error {
	if iface == nil {
		return nil
	}

	return iface.InterfaceLUID.DeleteIPAddress(*ip.IPNet)
}

func getInterface(ifname string) (ipv4, ipv6 *winipcfg.MibIPInterfaceRow, err error) {
	v4, err := winipcfg.GetIPInterfaceTable(windows.AF_INET)
	if err != nil {
		err = fmt.Errorf("failed to check ipv4 interfaces: %w", err)
		return
	}

	v6, err := winipcfg.GetIPInterfaceTable(windows.AF_INET6)
	if err != nil {
		err = fmt.Errorf("failed to check ipv6 interfaces: %w", err)
		return
	}

	ipv4 = findInterface(ifname, v4)
	ipv6 = findInterface(ifname, v6)

	return
}

func findInterface(ifname string, v4 []winipcfg.MibIPInterfaceRow) *winipcfg.MibIPInterfaceRow {
	for idx, i := range v4 {
		iface, err := net.InterfaceByIndex(int(i.InterfaceIndex))
		if err == nil && iface.Name == ifname {
			return &v4[idx]
		}
	}

	return nil
}
