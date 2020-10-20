package wireguard

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
	"arhat.dev/abbot/pkg/util"
	"arhat.dev/abbot/pkg/wrap/netlink"
)

const (
	DriverName = "wireguard"
)

func init() {
	driver.Register(DriverName, "darwin", NewDriver, NewConfig)
	driver.Register(DriverName, "freebsd", NewDriver, NewConfig)
	driver.Register(DriverName, "openbsd", NewDriver, NewConfig)
	driver.Register(DriverName, "windows", NewDriver, NewConfig)
	driver.Register(DriverName, "linux", NewDriver, NewConfig)
}

func NewDriver(ctx context.Context, cfg interface{}) (types.Driver, error) {
	config, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid non wireguard driver config")
	}

	ips, err := util.ParseIPs(config.Addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse addresses: %w", err)
	}

	var allAllowedIPs []string
	for _, p := range config.Peers {
		allAllowedIPs = append(allAllowedIPs, p.AllowedIps...)
	}

	allowedIPs, err := util.ParseIPNets(allAllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowed ips: %w", err)
	}

	wgCfg, err := config.GetWireGuardConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard config: %w", err)
	}

	return &Driver{
		ctx:    ctx,
		name:   config.Name,
		config: config,

		ips:           ips,
		allAllowedIPs: allowedIPs,

		wgCfg: wgCfg,

		mu: new(sync.Mutex),
	}, nil
}

type Driver struct {
	ctx context.Context

	name   string
	config *Config

	dev  *device.Device
	uapi net.Listener

	ips           map[string]*netlink.Addr
	allAllowedIPs map[string]*net.IPNet

	deleted bool
	wgCfg   *wgtypes.Config

	mu *sync.Mutex
}

func (d *Driver) Name() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.name
}

func (d *Driver) ensureEveryThing() error {
	err := d.ensureDeviceConfig()
	if err != nil {
		return err
	}

	err = ensureAddresses(d.name, d.ips)
	if err != nil {
		return err
	}

	if d.config.Routing.Enabled {
		err = ensureRoute(d.name, int(d.config.Routing.Table), d.allAllowedIPs)
		if err != nil && !strings.Contains(err.Error(), "down") {
			return err
		}
	}

	return nil
}

func (d *Driver) Ensure(up bool) (err error) {
	select {
	case <-d.ctx.Done():
		return nil
	default:
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.deleted {
		return nil
	}

	if d.dev != nil {
		err = d.ensureEveryThing()
		if err != nil {
			return err
		}

		d.ensureUp(up)

		return nil
	}

	tunDev, err := createTun(d.name, int(d.config.Mtu))
	if err != nil {
		return err
	}

	defer func() {
		defer func() {
			_ = recover()
		}()

		if err != nil {
			_ = tunDev.Close()
		}
	}()

	realName, err := tunDev.Name()
	if err == nil {
		d.name = realName
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

	logger := device.NewLogger(logLevel, fmt.Sprintf("[wg:%s]", d.name))

	uapi, err := listenUAPI(d.name)
	if err != nil {
		return fmt.Errorf("failed to listen on uapi socket: %w", err)
	}

	defer func() {
		defer func() {
			_ = recover()
		}()

		if err != nil {
			_ = uapi.Close()
		}
	}()

	dev := device.NewDevice(tunDev, logger)
	defer func() {
		defer func() {
			_ = recover()
		}()

		if err != nil {
			dev.Down()
			dev.Close()
		}
	}()

	errs := make(chan error)

	go func() {
		for {
			conn, err2 := uapi.Accept()
			if err2 != nil {
				errs <- err2
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

	d.ensureUp(up)

	return d.ensureEveryThing()
}

func (d *Driver) delete(recoverable bool) error {
	d.mu.Lock()
	defer func() {
		_ = recover()

		d.mu.Unlock()
	}()

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

	_ = ensureRoute(d.name, int(d.config.Routing.Table), nil)

	return nil
}

func (d *Driver) Delete() error {
	// no matter application exited or not, we should delete this device
	select {
	case <-d.ctx.Done():
	default:
	}
	return d.delete(false)
}

func (d *Driver) ensureDeviceConfig() error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}

	defer func() {
		_ = c.Close()
	}()

	var (
		updateConfig *wgtypes.Config
		currentDev   *wgtypes.Device
	)

	currentDev, err = c.Device(d.name)
	if err != nil {
		return fmt.Errorf("failed to inspect existing wireguard device: %w", err)
	}

	switch {
	case d.wgCfg.PrivateKey != nil &&
		!bytes.Equal(d.wgCfg.PrivateKey[:], currentDev.PrivateKey[:]),
		d.config.ListenPort > 0 && currentDev.ListenPort != int(d.config.ListenPort),
		currentDev.FirewallMark != int(d.config.Routing.FirewallMark):

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
				case expectedPeer.PresharedKey != nil &&
					!bytes.Equal(p.PresharedKey[:], expectedPeer.PresharedKey[:]),
					!bytes.Equal(p.PublicKey[:], expectedPeer.PublicKey[:]),
					expectedPeer.PersistentKeepaliveInterval != nil &&
						p.PersistentKeepaliveInterval != *expectedPeer.PersistentKeepaliveInterval,
					expectedPeer.Endpoint != nil &&
						(p.Endpoint == nil || p.Endpoint.String() != expectedPeer.Endpoint.String()),
					updateAllowedIPs:

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

	if updateConfig != nil {
		err = c.ConfigureDevice(d.name, *updateConfig)
		if err != nil {
			return fmt.Errorf("failed to configure wireguard device: %w", err)
		}
	}

	return nil
}
