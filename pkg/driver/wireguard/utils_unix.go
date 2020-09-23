// +build !windows

package wireguard

import (
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func createTun(ifname string, mtu int) (tun.Device, error) {
	tunFdStr := os.Getenv("WG_TUN_FD")
	if tunFdStr == "" {
		return tun.CreateTUN(ifname, mtu)
	}

	// construct tun device from supplied fd

	fd, err := strconv.ParseUint(tunFdStr, 10, 32)
	if err != nil {
		return nil, err
	}

	err = syscall.SetNonblock(int(fd), true)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "")
	return tun.CreateTUNFromFile(file, mtu)
}

func listenUAPI(ifname string) (_ net.Listener, err error) {
	var (
		fileUAPI *os.File
	)
	uapiFdStr := os.Getenv("WG_UAPI_FD")
	if uapiFdStr == "" {
		fileUAPI, err = ipc.UAPIOpen(ifname)
	} else {
		// use supplied fd
		var fd uint64
		fd, err = strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		fileUAPI = os.NewFile(uintptr(fd), "")
	}

	defer func() {
		if err != nil {
			_ = fileUAPI.Close()
		}
	}()

	return ipc.UAPIListen(ifname, fileUAPI)
}
