package bridge

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"

	"arhat.dev/abbot-proto/abbotgopb"
	"go.uber.org/multierr"

	"arhat.dev/abbot/pkg/types"
	"arhat.dev/abbot/pkg/util"
	"arhat.dev/abbot/pkg/wrap/netlink"
)

func (c *Config) GetLinkAttrs(name string) netlink.LinkAttrs {
	ret := netlink.NewLinkAttrs()
	ret.Name = name
	ret.Alias = c.Alias
	if c.Promisc {
		ret.Promisc = 1
	} else {
		ret.Promisc = 0
	}

	ret.MTU = int(c.Mtu)
	ret.TxQLen = int(c.TxQueueLen)
	if c.HardwareAddress != "" {
		ret.HardwareAddr, _ = net.ParseMAC(c.HardwareAddress)
	}
	ret.Protinfo = &netlink.Protinfo{
		Hairpin:      c.Hairpin,
		Guard:        c.Guard,
		FastLeave:    c.FastLeave,
		RootBlock:    c.RootBlock,
		Learning:     c.Learning,
		Flood:        c.Flood,
		ProxyArp:     c.ProxyArp,
		ProxyArpWiFi: c.ProxyArpWifi,
	}

	return ret
}

func NewDriver(ctx context.Context, cfg interface{}) (types.Driver, error) {
	var config *Config
	switch c := cfg.(type) {
	case *Config:
		config = c
	case *abbotgopb.HostNetworkInterface:
		if c.Metadata == nil {
			return nil, fmt.Errorf("no metadata provided")
		}
		if c.GetBridge() == nil {
			return nil, fmt.Errorf("invalid non bridge config")
		}
		config = &Config{
			NetworkInterface: *c.Metadata,
			DriverBridge:     *c.GetBridge(),
		}
	default:
		return nil, fmt.Errorf("unknown bridge config type: %s", reflect.TypeOf(cfg).String())
	}

	addrs, err := util.ParseIPs(config.Addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip addresses: %w", err)
	}

	return &Driver{
		ctx:  ctx,
		name: config.Name,

		h: &netlink.Handle{},

		ips:    addrs,
		config: config,
		mu:     new(sync.RWMutex),
	}, nil
}

type Driver struct {
	ctx  context.Context
	name string

	h *netlink.Handle

	ips    map[string]*netlink.Addr
	config *Config
	mu     *sync.RWMutex
}

func (d *Driver) Name() string {
	return d.name
}

func (d *Driver) updateLink(link netlink.Link) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var (
		err    error
		hwAddr net.HardwareAddr
		attrs  = link.Attrs()
	)

	if d.config.HardwareAddress != "" {
		hwAddr, err = net.ParseMAC(d.config.HardwareAddress)
		if err != nil {
			return fmt.Errorf("failed to parse hw address: %w", err)
		}
	}

	if attrs.Protinfo == nil {
		attrs.Protinfo = &netlink.Protinfo{}
	}

	for i := 0; i < 100; i++ {
		switch {
		case attrs.Alias != d.config.Alias:
			err = multierr.Append(err, d.h.LinkSetAlias(link, d.config.Alias))
			attrs.Alias = d.config.Alias
		case (attrs.Promisc != 0) != d.config.Promisc:
			if d.config.Promisc {
				err = multierr.Append(err, d.h.SetPromiscOn(link))
				attrs.Promisc = 1
			} else {
				err = multierr.Append(err, d.h.SetPromiscOff(link))
				attrs.Promisc = 0
			}
		case attrs.Protinfo.Flood != d.config.Flood:
			err = multierr.Append(err, d.h.LinkSetFlood(link, d.config.Flood))
			attrs.Protinfo.Flood = d.config.Flood
		case attrs.Protinfo.FastLeave != d.config.FastLeave:
			err = multierr.Append(err, d.h.LinkSetFastLeave(link, d.config.FastLeave))
			attrs.Protinfo.FastLeave = d.config.FastLeave
		case attrs.Protinfo.Guard != d.config.Guard:
			err = multierr.Append(err, d.h.LinkSetGuard(link, d.config.Guard))
			attrs.Protinfo.Guard = d.config.Guard
		case attrs.Protinfo.Hairpin != d.config.Hairpin:
			err = multierr.Append(err, d.h.LinkSetHairpin(link, d.config.Hairpin))
			attrs.Protinfo.Hairpin = d.config.Hairpin
		case attrs.Protinfo.Learning != d.config.Learning:
			err = multierr.Append(err, d.h.LinkSetLearning(link, d.config.Learning))
			attrs.Protinfo.Learning = d.config.Learning
		case attrs.Protinfo.ProxyArp != d.config.ProxyArp:
			err = multierr.Append(err, d.h.LinkSetBrProxyArp(link, d.config.ProxyArp))
			attrs.Protinfo.ProxyArp = d.config.ProxyArp
		case attrs.Protinfo.ProxyArpWiFi != d.config.ProxyArpWifi:
			err = multierr.Append(err, d.h.LinkSetBrProxyArpWiFi(link, d.config.ProxyArpWifi))
			attrs.Protinfo.ProxyArpWiFi = d.config.ProxyArpWifi
		case attrs.Protinfo.RootBlock != d.config.RootBlock:
			err = multierr.Append(err, d.h.LinkSetRootBlock(link, d.config.RootBlock))
			attrs.Protinfo.RootBlock = d.config.RootBlock
		case attrs.MTU != int(d.config.Mtu):
			err = multierr.Append(err, d.h.LinkSetMTU(link, int(d.config.Mtu)))
			attrs.MTU = int(d.config.Mtu)
		case attrs.TxQLen != int(d.config.TxQueueLen):
			err = multierr.Append(err, d.h.LinkSetTxQLen(link, int(d.config.TxQueueLen)))
			attrs.TxQLen = int(d.config.TxQueueLen)
		case len(hwAddr) > 0 && !bytes.Equal(attrs.HardwareAddr, hwAddr):
			err = multierr.Append(err, d.h.LinkSetHardwareAddr(link, hwAddr))
			attrs.HardwareAddr = hwAddr
		default:
			return err
		}
	}

	return nil
}

func (d *Driver) EnsureConfig(config *abbotgopb.HostNetworkInterface) error {
	if config.Metadata == nil {
		return fmt.Errorf("no metadata provided")
	}

	if config.GetBridge() == nil {
		return fmt.Errorf("not a wireguard interface")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.config = &Config{
		NetworkInterface: *config.Metadata,
		DriverBridge:     *config.GetBridge(),
	}
	link, err := d.h.LinkByName(d.name)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %w", d.name, err)
	}

	err = d.updateLink(link)
	if err != nil {
		return fmt.Errorf("failed to update link config %s: %w", d.name, err)
	}

	return nil
}

func (d *Driver) GetConfig() (*abbotgopb.HostNetworkInterface, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.config.castToHostNetworkInterface(d.name)
}

func (d *Driver) Ensure(up bool) error {
	var (
		name   = d.name
		create bool
	)

	link, err := d.h.LinkByName(name)
	if err != nil {
		if e, ok := err.(netlink.LinkNotFoundError); !ok {
			return fmt.Errorf("failed to check status of %s: %w", name, e)
		}

		create = true
	} else {
		if t := link.Type(); t != (&netlink.Bridge{}).Type() {
			// not a bridge link
			err = d.h.LinkDel(link)
			if err != nil {
				return fmt.Errorf("failed to delete unexpected link %s with type %s: %w", name, t, err)
			}

			create = true
		} else {
			// TODO: update link if attributes not up to date
			err = d.updateLink(link)
			if err != nil {
				return fmt.Errorf("failed to update link %s: %w", name, err)
			}
		}
	}

	if create {
		err = d.h.LinkAdd(&netlink.Bridge{
			LinkAttrs:         d.config.GetLinkAttrs(name),
			MulticastSnooping: nil,
			HelloTime:         nil,
		})
		if err != nil {
			return fmt.Errorf("failed to add link %s: %w", name, err)
		}
	}

	link, err = d.h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to recheck existing link %s: %w", name, err)
	}

	err = util.EnsureIPs(d.h, link, d.ips)
	if err != nil {
		return fmt.Errorf("failed to ensure link addresses: %w", err)
	}

	attrs := link.Attrs()
	switch {
	case up && (attrs.OperState != netlink.OperUp):
		err = d.h.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set link %s up: %w", name, err)
		}
	case !up && (attrs.OperState != netlink.OperDown):
		err = d.h.LinkSetDown(link)
		if err != nil {
			return fmt.Errorf("failed to set link %s down: %w", name, err)
		}
	}

	return nil
}

func (d *Driver) Delete() error {
	select {
	case <-d.ctx.Done():
		// application exited, this is a system device, keep it
		return nil
	default:
		// application still running, we should delete this device
	}

	var (
		name = d.name
	)

	link, err := d.h.LinkByName(name)
	if err != nil {
		if e, ok := err.(netlink.LinkNotFoundError); !ok {
			return fmt.Errorf("failed to check status of %s: %w", name, e)
		}

		return nil
	}

	err = d.h.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete link %s: %w", name, err)
	}

	return nil
}
