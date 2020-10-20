package usernet

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"arhat.dev/abbot-proto/abbotgopb"

	"arhat.dev/abbot/pkg/constant"

	"arhat.dev/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"

	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

func init() {
	driver.Register(constant.DriverUsernet, "aix", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "dragonfly", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "darwin", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "freebsd", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "openbsd", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "solaris", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "netbsd", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "windows", NewDriver, NewConfig)
	driver.Register(constant.DriverUsernet, "linux", NewDriver, NewConfig)
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

		// TODO: support usernet in abbot-proto
		//if c.GetWireguard() == nil {
		//	return nil, fmt.Errorf("invalid non usernet config")
		//}
		config = &Config{
			NetworkInterface: *c.Metadata,
		}
		return nil, fmt.Errorf("no abbot proto support for usernet")
	default:
		return nil, fmt.Errorf("unknown usernet config type: %s", reflect.TypeOf(cfg).String())
	}

	var rawFactory stack.RawFactory
	if config.ProtocolStack.Protocols.Raw.Enabled {
		rawFactory = &raw.EndpointFactory{}
	}

	opts := stack.Options{
		NetworkProtocols:   config.resolveNetworks(),
		TransportProtocols: config.resolveProtocols(),
		RawFactory:         rawFactory,
		Stats:              prometheusStats(),
	}

	netStack := stack.New(opts)
	nicID, ep, err := config.configureNetworks(ctx, netStack)
	if err != nil {
		return nil, fmt.Errorf("failed to configure network: %w", err)
	}

	err = config.ProtocolStack.configureProtocols(netStack)
	if err != nil {
		return nil, fmt.Errorf("failed to configure protocol: %w", err)
	}

	logger := log.Log.WithName(config.Name)
	var overlayDriver OverlayDriver
	overlay := config.Overlay
	switch {
	case overlay.MQTT != nil:
		overlayDriver, err = overlay.MQTT.createOverlayDriver(logger, ep)
	default:
		return nil, fmt.Errorf("no overlay configured")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create overlay driver: %w", err)
	}

	return &Driver{
		ctx:    ctx,
		logger: logger,
		name:   config.Name,

		overlay: overlayDriver,

		mtu:      int(config.Mtu),
		nicID:    nicID,
		netStack: netStack,

		ep:     ep,
		mu:     new(sync.RWMutex),
		config: config,

		running: make(chan struct{}),
	}, nil
}

type Driver struct {
	ctx    context.Context
	logger log.Interface
	name   string

	overlay OverlayDriver

	mtu      int
	netStack *stack.Stack
	ep       *channel.Endpoint
	mu       *sync.RWMutex
	config   *Config

	nicID tcpip.NICID

	running chan struct{}
}

func (d *Driver) DriverName() string {
	return constant.DriverUsernet
}

// Name of the interface
func (d *Driver) Name() string {
	return d.name
}

func (d *Driver) runningCh() <-chan struct{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.running
}

func (d *Driver) EnsureConfig(config *abbotgopb.HostNetworkInterface) error {
	return fmt.Errorf("unimplemented")
}

func (d *Driver) GetConfig() (*abbotgopb.HostNetworkInterface, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.config.castToHostNetworkInterface(d.name)
}

// Ensure up/down state of this interface
func (d *Driver) Ensure(up bool) error {
	select {
	case <-d.ctx.Done():
		return d.ctx.Err()
	case <-d.runningCh():
		if up {
			// running and is expected
			return nil
		}

		d.logger.I("disabling overlay and underlay network")
		// running but we want it down
		d.mu.Lock()
		d.netStack.DisableNIC(d.nicID)
		_ = d.overlay.Close()
		d.running = make(chan struct{})
		d.mu.Unlock()

		return nil
	default:
		// not running
	}
	if !up {
		// not running and expected
		return nil
	}

	d.logger.I("enabling underlay network and starting overlay network")

	// expected to be running
	d.netStack.EnableNIC(d.nicID)

	d.mu.Lock()
	close(d.running)
	d.mu.Unlock()

	runningCh := d.runningCh()
	go d.overlayRoutine(runningCh)
	go d.underlayRoutine(runningCh)

	return nil
}

// Delete this interface
func (d *Driver) Delete() error {
	d.netStack.Close()
	return nil
}

func (d *Driver) overlayRoutine(keepRunning <-chan struct{}) {
	for {
		select {
		case <-keepRunning:
			// expected to be running, reconnect
			err := d.overlay.Connect(d.ctx.Done())
			if err != nil {
				d.logger.I("failed to connect to overlay network", log.Error(err))
			}
		default:
			return
		}
	}
}

func (d *Driver) underlayRoutine(keepRunning <-chan struct{}) {
	pktData := make([]byte, d.mtu)
	for {
		select {
		case <-keepRunning:
			// expected to be running, read more
		default:
			return
		}

		pkt, more := d.ep.ReadContext(d.ctx)
		if !more {
			return
		}

		switch pkt.Proto {
		case ipv4.ProtocolNumber, ipv6.ProtocolNumber:
			// forward to overlay network
		case arp.ProtocolNumber:
			// TODO: handle arp packet
			continue
		default:
			continue
		}

		n := 0
		// ignore L2 data
		for _, v := range pkt.Pkt.Next().Views() {
			if v.IsEmpty() {
				continue
			}

			n += copy(pktData[n:], v)
		}

		buf := make([]byte, n)
		_ = copy(buf, pktData)

		d.overlay.SendPacket(buf)
	}
}
