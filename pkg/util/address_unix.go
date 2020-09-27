// +build !windows,!linux

package util

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"arhat.dev/abbot/pkg/wrap/netlink"
)

func EnsureIPs(ifname string, ipAddresses map[string]*netlink.Addr) error {
	actual, err := GetInterfaceIPs(ifname)
	if err != nil {
		return fmt.Errorf("failed to check ip addresses of device %s: %w", ifname, err)
	}

	toAdd, toDel := GetIPsToAddAndToDelete(actual, ipAddresses)

	for _, ip := range toDel {
		err = deleteIP(ifname, ip)
		if err != nil {
			return err
		}
	}

	for _, ip := range toAdd {
		err = addIP(ifname, ip)
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteIP(ifname string, addr *netlink.Addr) error {
	args := []string{ifname, "delete", strings.SplitN(addr.String(), "/", 2)[0]}
	cmd := exec.Command("ifconfig", append(args)...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(bytes.ToLower(data), []byte("can't assign")) {
			// already deleted
			return nil
		}

		return fmt.Errorf("failed to delete address %s for device %s: %s", addr, ifname, err)
	}

	return nil
}

func addIP(ifname string, addr *netlink.Addr) error {
	args := []string{ifname}

	ver := "inet"
	if addr.IP.To4() == nil {
		ver = "inet6"
	}

	args = append(args, ver, addr.String())

	switch {
	case strings.HasPrefix(ifname, "utun") && ver == "inet":
		args = append(args, strings.SplitN(addr.String(), "/", 2)[0])
	}

	cmd := exec.Command("ifconfig", append(args, "alias")...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to ensure address %s for device %s: %w", addr, ifname, err)
	}

	return nil
}
