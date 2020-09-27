// +build !linux,!windows

package util

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"arhat.dev/abbot/pkg/wrap/netlink"
)

func EnsureRoutes(ifname string, table int, ipRanges map[string]*net.IPNet) error {
	actual, err := getRoutes(ifname)
	if err != nil {
		return fmt.Errorf("failed to check route for device %s: %w", ifname, err)
	}

	toAdd, toDel := GetIPNetsToAddAndToDelete(actual, ipRanges)

	for k := range toDel {
		err = deleteRoute(table, k)
		if err != nil {
			return fmt.Errorf("failed to remove route %s for device %s: %w", k, ifname, err)
		}
	}

	for k := range toAdd {
		err = addRoute(ifname, table, k)
		if err != nil {
			return fmt.Errorf("failed to add route for device %s dest %s: %w", ifname, k, err)
		}
	}

	return nil
}

func getRoutes(ifname string) (map[string]*net.IPNet, error) {
	space := regexp.MustCompile(`\s+`)

	cmd := exec.Command("netstat", "-nr", "-f", "inet")
	data, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to check ipv4 routes for device %s: %w", ifname, err)
	}

	var ret []string
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, ifname) {
			continue
		}

		parts := strings.Split(space.ReplaceAllString(line, " "), " ")
		if len(parts) < 6 {
			continue
		}

		dest, gw, name := parts[0], parts[1], parts[5]
		if name == ifname || gw == ifname {
			ret = append(ret, dest)
		}
	}

	cmd = exec.Command("netstat", "-nr", "-f", "inet6")
	data, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to check ipv4 routes for device %s: %w", ifname, err)
	}
	s = bufio.NewScanner(bytes.NewReader(data))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, ifname) {
			continue
		}

		parts := strings.Split(space.ReplaceAllString(line, " "), " ")
		if len(parts) < 4 {
			continue
		}

		dest, gw, name := parts[0], parts[1], parts[3]
		if name == ifname || gw == ifname {
			ret = append(ret, dest)
		}
	}

	result := make(map[string]*net.IPNet)
	for _, r := range ret {
		ipNet, err := netlink.ParseIPNet(r)
		if err != nil {
			// TODO: handle single ip, e.g. `10.0.0.1`

			//ip := net.ParseIP(r)
			//if ip == nil {
			//	return nil, fmt.Errorf("invalid ip net %s", r)
			//}
			//
			//mask := ip.DefaultMask()
			//ones, _ := mask.Size()
			//result[r+"/"+strconv.FormatInt(int64(ones), 10)] = &net.IPNet{IP: ip, Mask: mask}
		} else {
			result[r] = ipNet
		}
	}

	return result, nil
}

func deleteRoute(table int, ipRange string) error {
	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return fmt.Errorf("invalid ip range %s: %w", ipRange, err)
	}

	ver := "-inet"
	if ip.To4() == nil {
		ver = "-inet6"
	}

	args := []string{
		"-q", "-n", "delete", ver, ipNet.String(),
	}

	cmd := exec.Command("route", append(args)...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(bytes.ToLower(data), []byte("")) {
			return nil
		}

		return fmt.Errorf("failed to delete route for ip range %s: %w", ipRange, err)
	}

	return nil
}

func addRoute(ifname string, table int, ipRange string) error {
	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return fmt.Errorf("invalid ip range %s: %w", ipRange, err)
	}

	ver := "-inet"
	if ip.To4() == nil {
		ver = "-inet6"
	}

	args := []string{
		"-q", "-n", "add", ver, ipNet.String(), "-interface", ifname,
	}

	if runtime.GOOS != "darwin" {
		args = append(args, "-fib", strconv.FormatInt(int64(table), 10))
	}

	cmd := exec.Command("route", append(args)...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(bytes.ToLower(data), []byte("")) {
			return nil
		}

		return fmt.Errorf("failed to add route for ip range %s to device %s: %w", ipRange, ifname, err)
	}

	return nil
}
