package wireguard

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

func init() {
	driver.Register("wireguard", "darwin", NewDriver, NewConfig)
	driver.Register("wireguard", "freebsd", NewDriver, NewConfig)
	driver.Register("wireguard", "openbsd", NewDriver, NewConfig)
	driver.Register("wireguard", "windows", NewDriver, NewConfig)
	driver.Register("wireguard", "linux", NewDriver, NewConfig)
}

func NewConfig() interface{} {
	return &Config{
		Name: "",
		MTU:  device.DefaultMTU,
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

type Config struct {
	Name     string `json:"name" yaml:"name"`
	MTU      int    `json:"mtu" yaml:"mtu"`
	LogLevel string `json:"logLevel" yaml:"logLevel"`

	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the private key.
	PrivateKey string `json:"privateKey" yaml:"privateKey"`

	// ListenPort specifies a device's listening port, if not nil.
	ListenPort int `json:"listenPort" yaml:"listenPort"`

	// FirewallMark specifies a device's firewall mark, if not nil.
	//
	// If non-nil and set to 0, the firewall mark will be cleared.
	FirewallMark int `json:"firewallMark" yaml:"firewallMark"`

	// Peers specifies a list of peer configurations to apply to a device.
	Peers []PeerConfig `json:"peers" yaml:"peers"`
}

func decodeKey(data, kind, target string) (wgtypes.Key, error) {
	pk, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("invalid base64 encoded %s for %s: %w", kind, target, err)
	}

	if len(pk) != len(wgtypes.Key{}) {
		return wgtypes.Key{}, fmt.Errorf("invalid key %s", data)
	}

	ret := wgtypes.Key{}
	copy(ret[:], pk[:])

	return ret, nil
}

func (c *Config) GetWireGuardConfig() (*wgtypes.Config, error) {
	var peers []wgtypes.PeerConfig
	for _, p := range c.Peers {
		addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid udp endpoint %s: %w", addr, err)
		}

		var allowedIPs []net.IPNet
		for _, ip := range p.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, fmt.Errorf("failed to parse net cidr %s: %w", ip, err)
			}

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
			if c.FirewallMark != 0 {
				return &c.FirewallMark
			}
			return nil
		}(),
		ReplacePeers: true,
		Peers:        peers,
	}, nil
}

func NewDriver(cfg interface{}) (types.Driver, error) {
	config, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid non tun driver config")
	}

	return &Driver{
		config: config,
		mu:     new(sync.Mutex),
	}, nil
}

type Driver struct {
	config *Config

	dev  *device.Device
	uapi net.Listener

	deleted bool
	wgCfg   *wgtypes.Config

	mu *sync.Mutex
}

func (d *Driver) ensureDeviceConfig() error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer func() {
		_ = c.Close()
	}()

	var updateConfig *wgtypes.Config
	if d.wgCfg == nil {
		d.wgCfg, err = d.config.GetWireGuardConfig()
		if err != nil {
			return fmt.Errorf("failed to generate wireguard config: %w", err)
		}

		updateConfig = d.wgCfg
	} else {
		var currentDev *wgtypes.Device
		currentDev, err = c.Device(d.config.Name)
		if err != nil {
			return fmt.Errorf("failed to inspect existing wireguard device: %w", err)
		}

		switch {
		case d.wgCfg.PrivateKey != nil &&
			!bytes.Equal(d.wgCfg.PrivateKey[:], currentDev.PrivateKey[:]),
			currentDev.ListenPort != d.config.ListenPort,
			currentDev.FirewallMark != d.config.FirewallMark:

			// device not update to date, need to update
			updateConfig = &wgtypes.Config{
				PrivateKey:   d.wgCfg.PrivateKey,
				ListenPort:   d.wgCfg.ListenPort,
				FirewallMark: d.wgCfg.FirewallMark,
				ReplacePeers: true,
				Peers:        d.wgCfg.Peers,
			}
		default:
			var peerConfigs []wgtypes.PeerConfig

			expectedPeers := make(map[string]*wgtypes.PeerConfig)
			for i, p := range d.wgCfg.Peers {
				expectedPeers[hex.EncodeToString(p.PublicKey[:])] = &d.wgCfg.Peers[i]
			}
			for i, p := range currentDev.Peers {
				peerKey := hex.EncodeToString(p.PublicKey[:])
				expectedPeer, ok := expectedPeers[peerKey]
				if !ok {
					peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
						PublicKey:                   currentDev.Peers[i].PublicKey,
						Remove:                      true,
						UpdateOnly:                  false,
						PresharedKey:                &currentDev.Peers[i].PresharedKey,
						Endpoint:                    currentDev.Peers[i].Endpoint,
						PersistentKeepaliveInterval: &currentDev.Peers[i].PersistentKeepaliveInterval,
						ReplaceAllowedIPs:           false,
						AllowedIPs:                  currentDev.Peers[i].AllowedIPs,
					})
				} else {
					expectedIPs := make(map[string]struct{})
					for _, allowedIP := range expectedPeer.AllowedIPs {
						expectedIPs[allowedIP.String()] = struct{}{}
					}

					updateAllowedIPs := false
					for _, ip := range p.AllowedIPs {
						ipKey := ip.String()
						_, ok = expectedIPs[ipKey]
						if !ok {
							updateAllowedIPs = true
							break
						}
						delete(expectedIPs, ipKey)
					}
					if !updateAllowedIPs {
						updateAllowedIPs = len(expectedIPs) != 0
					}

					switch {
					case !bytes.Equal(p.PresharedKey[:], expectedPeer.PresharedKey[:]),
						!bytes.Equal(p.PublicKey[:], expectedPeer.PublicKey[:]),
						expectedPeer.PersistentKeepaliveInterval != nil &&
							p.PersistentKeepaliveInterval != *expectedPeer.PersistentKeepaliveInterval,
						p.Endpoint.String() != expectedPeer.Endpoint.String(), updateAllowedIPs:

						peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
							PublicKey:                   expectedPeer.PublicKey,
							Remove:                      false,
							UpdateOnly:                  true,
							PresharedKey:                expectedPeer.PresharedKey,
							Endpoint:                    expectedPeer.Endpoint,
							PersistentKeepaliveInterval: expectedPeer.PersistentKeepaliveInterval,
							ReplaceAllowedIPs:           updateAllowedIPs,
							AllowedIPs:                  expectedPeer.AllowedIPs,
						})
					default:
						delete(expectedPeers, peerKey)
					}
				}

			}

			if len(peerConfigs) != 0 {
				updateConfig = &wgtypes.Config{
					PrivateKey:   d.wgCfg.PrivateKey,
					ListenPort:   d.wgCfg.ListenPort,
					FirewallMark: d.wgCfg.FirewallMark,
					ReplacePeers: false,
					Peers:        peerConfigs,
				}
			}
		}
	}

	if updateConfig != nil {
		err = c.ConfigureDevice(d.config.Name, *updateConfig)
		if err != nil {
			return fmt.Errorf("failed to configure wireguard device: %w", err)
		}
	}

	return nil
}

func (d *Driver) Ensure(up bool) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.deleted {
		return nil
	}

	if d.dev != nil {
		err = d.ensureDeviceConfig()
		if err != nil {
			return err
		}

		if up {
			d.dev.Up()
		} else {
			d.dev.Down()
		}

		return nil
	}

	tunDev, err := createTun(d.config.Name, d.config.MTU)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tunDev.Close()
		}
	}()

	realName, err := tunDev.Name()
	if err == nil {
		d.config.Name = realName
	}

	logLevel, ok := map[string]int{
		"":       device.LogLevelError,
		"debug":  device.LogLevelDebug,
		"silent": device.LogLevelSilent,
		"error":  device.LogLevelError,
		"info":   device.LogLevelInfo,
	}[strings.ToLower(d.config.LogLevel)]
	if !ok {
		return fmt.Errorf("invalid log level %s, must be one of [debug, info, error, silent]", d.config.LogLevel)
	}

	logger := device.NewLogger(logLevel, fmt.Sprintf("[wg:%s]", d.config.Name))
	fileUAPI, err := openUAPI(d.config.Name)

	defer func() {
		if err != nil {
			_ = fileUAPI.Close()
		}
	}()

	errs := make(chan error)

	uapi, err := ipc.UAPIListen(d.config.Name, fileUAPI)
	if err != nil {
		return fmt.Errorf("failed to listen on uapi socket: %w", err)
	}

	defer func() {
		if err != nil {
			_ = uapi.Close()
		}
	}()

	dev := device.NewDevice(tunDev, logger)
	defer func() {
		if err != nil {
			dev.Down()
			dev.Close()
		}
	}()

	if up {
		dev.Up()
	} else {
		dev.Down()
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}

			go dev.IpcHandle(conn)
		}
	}()

	go func() {
		select {
		case <-errs:
		case <-dev.Wait():
		}

		// unexpected exit, cleanup and ensure
		_ = d.delete(true)
		_ = d.Ensure(up)
	}()

	d.dev = dev
	d.uapi = uapi

	err = d.ensureDeviceConfig()
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) delete(recoverable bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !recoverable {
		d.deleted = true
	}

	if d.uapi != nil {
		_ = d.uapi.Close()
		d.uapi = nil
	}

	if d.dev != nil {
		d.dev.Close()
		d.dev = nil
	}

	return nil
}

func (d *Driver) Delete() error {
	return d.delete(false)
}

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
	return tun.CreateTUNFromFile(file, device.DefaultMTU)
}

func openUAPI(ifname string) (*os.File, error) {
	uapiFdStr := os.Getenv("WG_UAPI_FD")
	if uapiFdStr == "" {
		return ipc.UAPIOpen(ifname)
	}

	// use supplied fd

	fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(fd), ""), nil
}
