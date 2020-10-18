package usernet

import (
	"context"
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"

	"arhat.dev/abbot/pkg/driver"
	"arhat.dev/abbot/pkg/types"
)

const (
	DriverName = "usernet"
)

func init() {
	driver.Register(DriverName, "aix", NewDriver, NewConfig)
	driver.Register(DriverName, "dragonfly", NewDriver, NewConfig)
	driver.Register(DriverName, "darwin", NewDriver, NewConfig)
	driver.Register(DriverName, "freebsd", NewDriver, NewConfig)
	driver.Register(DriverName, "openbsd", NewDriver, NewConfig)
	driver.Register(DriverName, "solaris", NewDriver, NewConfig)
	driver.Register(DriverName, "netbsd", NewDriver, NewConfig)
	driver.Register(DriverName, "windows", NewDriver, NewConfig)
	driver.Register(DriverName, "linux", NewDriver, NewConfig)
}

func NewDriver(ctx context.Context, name string, cfg interface{}) (types.Driver, error) {
	config, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid non usernet driver config")
	}

	var rawFactory stack.RawFactory
	if config.ProtocolStack.Protocols.Raw.Enabled {
		rawFactory = &raw.EndpointFactory{}
	}

	opts := stack.Options{
		NetworkProtocols:   config.ProtocolStack.resolveNetworks(),
		TransportProtocols: config.ProtocolStack.resolveProtocols(),
		RawFactory:         rawFactory,
		Stats:              prometheusStats(),
	}

	netStack := stack.New(opts)
	ch, err := config.ProtocolStack.configureNetworks(ctx, name, netStack)
	if err != nil {
		return nil, fmt.Errorf("failed to configure network: %w", err)
	}

	err = config.ProtocolStack.configureProtocols(netStack)
	if err != nil {
		return nil, fmt.Errorf("failed to configure protocol: %w", err)
	}

	return &Driver{
		ctx:      ctx,
		name:     name,
		netStack: netStack,

		ch: ch,
		mu: new(sync.RWMutex),
	}, nil
}

type Driver struct {
	ctx      context.Context
	name     string
	netStack *stack.Stack

	ch      *channel.Endpoint
	mu      *sync.RWMutex
	running bool
}

// Name of the interface
func (d *Driver) Name() string {
	return d.name
}

// Ensure up/down state of this interface
func (d *Driver) Ensure(up bool) error {
	d.mu.RLock()
	if d.running {
		d.mu.RUnlock()
		return nil
	}
	d.mu.RUnlock()

	go func() {
		d.routine()
	}()

	return nil
}

// Delete this interface
func (d *Driver) Delete() error {
	d.netStack.Close()
	return nil
}

func (d *Driver) routine() {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	for {
		pkt, more := d.ch.ReadContext(d.ctx)
		if !more {
			return
		}

		switch pkt.Proto {
		case ipv4.ProtocolNumber:
		case ipv6.ProtocolNumber:
		case arp.ProtocolNumber:
		default:
			continue
		}

		for _, v := range pkt.Pkt.Views() {
			if v.IsEmpty() {
				continue
			}
		}
	}
}
