package wireguard

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func NewConfig() interface{} {
	return &Config{
		MTU:      device.DefaultMTU,
		LogLevel: "silent",
		Routing: RoutingConfig{
			Enabled:      true,
			Table:        0,
			FirewallMark: 0,
		},
	}
}

type PeerConfig struct {
	// PublicKey specifies the public key of this peer.  PublicKey is a
	// mandatory field for all PeerConfigs.
	PublicKey string `json:"publicKey" yaml:"publicKey"`

	// PresharedKey specifies a peer's preshared key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the preshared key.
	PresharedKey string `json:"preSharedKey" yaml:"preSharedKey"`

	// Endpoint specifies the endpoint of this peer entry, if not nil.
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// PersistentKeepaliveInterval specifies the persistent keepalive interval
	// for this peer, if not nil.
	//
	// A non-nil value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval time.Duration `json:"persistentKeepaliveInterval" yaml:"persistentKeepaliveInterval"`

	// AllowedIPs specifies a list of allowed IP addresses in CIDR notation
	// for this peer.
	AllowedIPs []string `json:"allowedIPs" yaml:"allowedIPs"`
}

type RoutingConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Table to add routes, if not set (0), will use default route table
	Table int `json:"table" yaml:"table"`

	// FirewallMark specifies a device's firewall mark, if not set.
	//
	// If non-nil and set to 0, the firewall mark will be cleared.
	FirewallMark int `json:"firewallMark" yaml:"firewallMark"`
}

type Config struct {
	Addresses []string `json:"addresses" yaml:"addresses"`
	MTU       int      `json:"mtu" yaml:"mtu"`

	LogLevel string `json:"logLevel" yaml:"logLevel"`

	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the private key.
	PrivateKey string `json:"privateKey" yaml:"privateKey"`

	// ListenPort specifies a device's listening port, if not nil.
	ListenPort int `json:"listenPort" yaml:"listenPort"`

	Routing RoutingConfig `json:"routing" yaml:"routing"`

	// Peers specifies a list of peer configurations to apply to a device.
	Peers []PeerConfig `json:"peers" yaml:"peers"`
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
		for _, ip := range p.AllowedIPs {
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
		if p.PresharedKey != "" {
			var pskData wgtypes.Key
			pskData, err = decodeKey(p.PresharedKey, "pre shared key", p.Endpoint)
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
				if p.PersistentKeepaliveInterval != 0 {
					return &p.PersistentKeepaliveInterval
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
			if c.ListenPort != 0 {
				return &c.ListenPort
			}
			return nil
		}(),
		FirewallMark: func() *int {
			if c.Routing.FirewallMark != 0 {
				return &c.Routing.FirewallMark
			}
			return nil
		}(),
		ReplacePeers: true,
		Peers:        peers,
	}, nil
}
