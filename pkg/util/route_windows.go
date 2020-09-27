package util

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func EnsureRoutes(ifname string, ipRanges map[string]*net.IPNet) error {
	v4, v6, err := getInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to find target device %s: %w", ifname, err)
	}

	rv4, rv6, err := getRoutes(v4, v6)
	if err != nil {
		return fmt.Errorf("failed to get routes for device %s: %w", ifname, err)
	}

	var v4Ranges, v6Ranges []*net.IPNet
	for _, r := range ipRanges {
		if r.IP.To4() == nil {
			v6Ranges = append(v6Ranges, r)
		} else {
			v4Ranges = append(v4Ranges, r)
		}
	}

	err = ensureRoutes(v4, rv4, v4Ranges)
	if err != nil {
		return fmt.Errorf("failed to ensure ipv4 routes for device %s: %w", ifname, err)
	}

	err = ensureRoutes(v6, rv6, v6Ranges)
	if err != nil {
		return fmt.Errorf("failed to ensure ipv6 routes for device %s: %w", ifname, err)
	}

	return nil
}

func ensureRoutes(iface *winipcfg.MibIPInterfaceRow, actual []*winipcfg.MibIPforwardRow2, expected []*net.IPNet) error {
	if iface == nil {
		return nil
	}

	var toRemove []net.IPNet
	for _, r := range actual {
		found := false
		var (
			j   int
			exp *net.IPNet
		)
		for j, exp = range expected {
			n := r.DestinationPrefix.IPNet()
			if (&n).String() == exp.String() {
				found = true
			}
		}

		if !found {
			toRemove = append(toRemove, r.DestinationPrefix.IPNet())
		} else {
			expected = append(expected[:j], expected[j+1:]...)
		}
	}

	for _, r := range toRemove {
		err := iface.InterfaceLUID.DeleteRoute(r, net.IP{})
		if err != nil {
			return fmt.Errorf("failed to delete route for ip net %s: %w", r.String(), err)
		}
	}

	for _, r := range expected {
		err := iface.InterfaceLUID.AddRoute(*r, nil, 0)
		if err != nil {
			return fmt.Errorf("failed to create forward rule for ip net %s: %w", r.String(), err)
		}
	}

	return nil
}

func getRoutes(v4, v6 *winipcfg.MibIPInterfaceRow) (ipv4, ipv6 []*winipcfg.MibIPforwardRow2, err error) {
	if v4 != nil {
		ipftv4, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
		if err != nil {
			err = fmt.Errorf("failed to check ipv4 forward table: %w", err)
			return
		}

		for i, ft := range ipftv4 {
			switch {
			case ft.InterfaceIndex == v4.InterfaceIndex,
				ft.InterfaceLUID == v4.InterfaceLUID:
				ipv4 = append(ipv4, &ipftv4[i])
			}
		}
	}

	if v6 != nil {
		ipftv6, err := winipcfg.GetIPForwardTable2(windows.AF_INET6)
		if err != nil {
			err = fmt.Errorf("failed to check ipv6 forward table: %w", err)
			return
		}

		for i, ft := range ipftv6 {
			switch {
			case ft.InterfaceIndex == v6.InterfaceIndex,
				ft.InterfaceLUID == v6.InterfaceLUID:
				ipv6 = append(ipv6, &ipftv6[i])
			}
		}
	}

	return
}
