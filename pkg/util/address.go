package util

import (
	"fmt"
	"net"

	"arhat.dev/abbot/pkg/wrap/netlink"
)

func GetInterfaceIPs(ifname string) (map[string]*netlink.Addr, error) {
	f, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", ifname, err)
	}

	addrs, err := f.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to check addresses of interface %s: %w", ifname, err)
	}

	ret := make(map[string]*netlink.Addr)
	for _, addr := range addrs {
		s := addr.String()
		a, err := netlink.ParseAddr(s)
		if err != nil {
			// should not happen
			return nil, fmt.Errorf("failed to parse interface address %s: %w", s, err)
		}
		ret[s] = a
	}

	return ret, nil
}

func ParseIPs(ips []string) (map[string]*netlink.Addr, error) {
	ret := make(map[string]*netlink.Addr)
	for _, ip := range ips {
		addr, err := netlink.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid ip %s: %w", ip, err)
		}
		ret[addr.String()] = addr
	}

	return ret, nil
}

func ParseIPNets(ipNets []string) (map[string]*net.IPNet, error) {
	ret := make(map[string]*net.IPNet)
	for _, ip := range ipNets {
		n, err := netlink.ParseIPNet(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid ip net %s: %w", ip, err)
		}

		ret[n.String()] = n
	}

	return ret, nil
}

func GetIPNetsToAddAndToDelete(actual, expected map[string]*net.IPNet) (toAdd, toDel map[string]*net.IPNet) {
	toAdd = make(map[string]*net.IPNet)

	for k := range expected {
		if _, ok := actual[k]; ok {
			// expected and exists
			delete(actual, k)
		} else {
			// expected but not exists
			toAdd[k] = expected[k]
		}
	}

	return toAdd, actual
}

func GetIPsToAddAndToDelete(actual, expected map[string]*netlink.Addr) (toAdd, toDel map[string]*netlink.Addr) {
	toAdd = make(map[string]*netlink.Addr)

	for k := range expected {
		if _, ok := actual[k]; ok {
			// expected and exists
			delete(actual, k)
		} else {
			// expected but not exists
			toAdd[k] = expected[k]
		}
	}

	return toAdd, actual
}
