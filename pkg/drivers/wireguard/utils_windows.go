package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func createTun(ifname string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(ifname, mtu)
}

func listenUAPI(ifname string) (net.Listener, error) {
	return ipc.UAPIListen(ifname)
}
