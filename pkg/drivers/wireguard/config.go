package wireguard

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"arhat.dev/abbot-proto/abbotgopb"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func NewConfig() interface{} {
	return &Config{
		NetworkInterface: abbotgopb.NetworkInterface{
			Name:            "",
			Mtu:             device.DefaultMTU,
			HardwareAddress: "",
			Addresses:       nil,
			DeleteOnExit:    false,
		},
		DriverWireguard: abbotgopb.DriverWireguard{
			LogLevel:   "silent",
			PrivateKey: "",
			ListenPort: 0,
			Routing: &abbotgopb.DriverWireguard_Routing{
				Enabled:      true,
				Table:        0,
				FirewallMark: 0,
			},
			Peers: nil,
		},
	}
}

type Config struct {
	abbotgopb.NetworkInterface `json:",inline" yaml:",inline"`
	abbotgopb.DriverWireguard  `json:",inline" yaml:",inline"`
}

func (c *Config) castToHostNetworkInterface(name string) (*abbotgopb.HostNetworkInterface, error) {
	metadataBytes, err := c.NetworkInterface.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal network metadata: %w", err)
	}

	configBytes, err := c.DriverWireguard.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wireguard config: %w", err)
	}

	md := new(abbotgopb.NetworkInterface)
	_ = md.Unmarshal(metadataBytes)
	cfg := new(abbotgopb.DriverWireguard)
	_ = cfg.Unmarshal(configBytes)

	md.Name = name

	return &abbotgopb.HostNetworkInterface{
		Metadata: md,
		Config:   &abbotgopb.HostNetworkInterface_Wireguard{Wireguard: cfg},
	}, nil
}

func decodeKey(data, kind, target string) (wgtypes.Key, error) {
	k, err := wgtypes.ParseKey(data)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("invalid %s for %s: %w", kind, target, err)
	}

	return k, nil
}

func (c *Config) GetWireGuardConfig() (*wgtypes.Config, error) {
	var peers []wgtypes.PeerConfig

	allowedIPsCheck := make(map[string]struct{})
	for _, p := range c.Peers {
		var (
			addr *net.UDPAddr
			err  error
		)
		if p.Endpoint != "" {
			addr, err = net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid udp endpoint %s: %w", addr, err)
			}
		}

		var allowedIPs []net.IPNet
		for _, ip := range p.AllowedIps {
			_, ipNet, err2 := net.ParseCIDR(ip)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse net cidr %s: %w", ip, err2)
			}

			netStr := ipNet.String()
			if _, dup := allowedIPsCheck[netStr]; dup {
				return nil, fmt.Errorf("invalid peers config contains duplicate allowed ips in different peers")
			}
			allowedIPsCheck[netStr] = struct{}{}
			allowedIPs = append(allowedIPs, *ipNet)
		}

		pk, err := decodeKey(p.PublicKey, "public key", p.Endpoint)
		if err != nil {
			return nil, err
		}

		var psk *wgtypes.Key
		if p.PreSharedKey != "" {
			var pskData wgtypes.Key
			pskData, err = decodeKey(p.PreSharedKey, "pre-shared key", p.Endpoint)
			if err != nil {
				return nil, err
			}
			psk = &pskData
		}

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:    pk,
			Remove:       false,
			UpdateOnly:   false,
			PresharedKey: psk,
			Endpoint:     addr,
			PersistentKeepaliveInterval: func() *time.Duration {
				if dur := time.Duration(p.PersistentKeepaliveInterval) * time.Second; dur != 0 {
					return &dur
				}
				return nil
			}(),
			ReplaceAllowedIPs: false,
			AllowedIPs:        allowedIPs,
		})
	}

	var pk *wgtypes.Key
	if c.PrivateKey != "" {
		pkData, err := decodeKey(c.PrivateKey, "private key", strconv.FormatInt(int64(c.ListenPort), 10))
		if err != nil {
			return nil, err
		}
		pk = &pkData
	}

	return &wgtypes.Config{
		PrivateKey: pk,
		ListenPort: func() *int {
			if p := int(c.ListenPort); p > 0 {
				return &p
			}
			return nil
		}(),
		FirewallMark: func() *int {
			if m := int(c.Routing.FirewallMark); m != 0 {
				return &m
			}
			return nil
		}(),
		ReplacePeers: true,
		Peers:        peers,
	}, nil
}
