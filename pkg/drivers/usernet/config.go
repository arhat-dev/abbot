package usernet

import (
	"context"
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"strings"
	"time"

	"arhat.dev/abbot-proto/abbotgopb"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"arhat.dev/abbot/pkg/util"
)

func NewConfig() interface{} {
	return &Config{
		NetworkInterface: abbotgopb.NetworkInterface{
			Name:            "",
			Mtu:             65535,
			HardwareAddress: "",
			Addresses:       nil,
			DeleteOnExit:    false,
		},
		Overlay: OverlayConfig{
			MQTT: nil,
		},
		ProtocolStack: StackConfig{
			ChannelSize: 256,
			Networks: StackNetworks{
				ARP: StackARPConfig{
					Enabled: false,
				},
				IPv4: StackIPv4Config{
					Enabled: true,
				},
				IPv6: StackIPv6Config{
					Enabled: false,
				},
			},
			Protocols: StackProtocols{
				Raw: StackRawConfig{
					Enabled: false,
				},
				ICMP: StackICMPConfig{
					Enabled: false,
				},
				TCP: StackTCPConfig{
					Enabled: true,
					SAck:    true,
					NoDelay: true,
					Buffer: SendRecvBufferConfig{
						Send: BufferConfig{
							Min:     4096,
							Max:     2 * 1024 * 1024,
							Default: 2 * 1024 * 1024,
						},
						Recv: BufferConfig{
							Min:     4096,
							Max:     2 * 1024 * 1024,
							Default: 2 * 1024 * 1024,
						},
					},
				},
				UDP: StackUDPConfig{
					Enabled: false,
				},
			},
		},
	}
}

type Config struct {
	abbotgopb.NetworkInterface `json:",inline" yaml:",inline"`
	Overlay                    OverlayConfig `json:"overlay" yaml:"overlay"`
	ProtocolStack              StackConfig   `json:"protocolStack" yaml:"protocolStack"`
}

func (c *Config) castToHostNetworkInterface(name string) (*abbotgopb.HostNetworkInterface, error) {
	metadataBytes, err := c.NetworkInterface.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal network metadata: %w", err)
	}

	//configBytes, err := c.DriverWireguard.Marshal()
	//if err != nil {
	//	return nil, fmt.Errorf("failed to marshal wireguard config: %w", err)
	//}

	md := new(abbotgopb.NetworkInterface)
	_ = md.Unmarshal(metadataBytes)
	//cfg := new(abbotgopb.DriverWireguard)
	//_ = cfg.Unmarshal(configBytes)

	md.Name = name

	return &abbotgopb.HostNetworkInterface{
		Metadata: md,
		Config:   &abbotgopb.HostNetworkInterface_Unknown{},
	}, nil
}

type OverlayConfig struct {
	MQTT *MQTTOverlayConfig `json:"mqtt" yaml:"mqtt"`
}

type StackConfig struct {
	ChannelSize int `json:"channelSize" yaml:"channelSize"`

	Networks  StackNetworks  `json:"networks" yaml:"networks"`
	Protocols StackProtocols `json:"protocols" yaml:"protocols"`
}

func (c Config) resolveNetworks() []stack.NetworkProtocolFactory {
	var ret []stack.NetworkProtocolFactory
	if c.ProtocolStack.Networks.ARP.Enabled {
		ret = append(ret, arp.NewProtocol)
	}
	if c.ProtocolStack.Networks.IPv4.Enabled {
		ret = append(ret, ipv4.NewProtocol)
	}

	if c.ProtocolStack.Networks.IPv6.Enabled {
		ret = append(ret, ipv6.NewProtocol)
	}

	return ret
}

func (c Config) configureNetworks(
	ctx context.Context, netStack *stack.Stack,
) (tcpip.NICID, *channel.Endpoint, error) {
	err := c.ProtocolStack.Networks.ARP.configure(netStack)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to configure arp network: %w", err)
	}

	err = c.ProtocolStack.Networks.IPv4.configure(netStack)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to configure ipv4 network: %w", err)
	}

	err = c.ProtocolStack.Networks.IPv6.configure(netStack)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to configure ipv6 network: %w", err)
	}

	nicID := tcpip.NICID(crc32.ChecksumIEEE([]byte(c.Name)))

	var hwAddr tcpip.LinkAddress
	if c.HardwareAddress == "" {
		buf := make([]byte, 6)
		_, err = rand.Read(buf)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to generate random hardware address: %w", err)
		}

		// set local bit and ensure unicast address
		buf[0] = (buf[0] | 2) & 0xfe
		hwAddr = tcpip.LinkAddress(buf)
	} else {
		var err2 error
		hwAddr, err2 = tcpip.ParseMACAddress(c.HardwareAddress)
		if err2 != nil {
			return 0, nil, fmt.Errorf("failed to parse hardware address: %w", err2)
		}
	}

	mtu := uint32(c.Mtu)
	if mtu == 0 {
		mtu = 65536
	}

	chSize := c.ProtocolStack.ChannelSize
	if chSize == 0 {
		chSize = 256
	}

	ep := channel.New(chSize, mtu, hwAddr)
	err2 := netStack.CreateNICWithOptions(nicID, ep, stack.NICOptions{
		Name:     c.Name,
		Disabled: false,
		Context:  ctx,
	})
	if err2 != nil {
		return 0, nil, fmt.Errorf("failed to create nic %s: %s", c.Name, err2.String())
	}

	addresses, err := util.ParseIPs(c.Addresses)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse ips: %w", err)
	}

	for _, addr := range addresses {
		if addr.IP.To4() == nil {
			err2 = netStack.AddAddress(nicID, ipv6.ProtocolNumber, tcpip.Address(addr.IP))
		} else {
			err2 = netStack.AddAddress(nicID, ipv4.ProtocolNumber, tcpip.Address(addr.IP))
		}
		if err2 != nil {
			return 0, nil, fmt.Errorf("failed to address %s to nic %s: %s", addr.String(), c.Name, err2.String())
		}
	}

	if c.ProtocolStack.Networks.ARP.Enabled {
		err2 = netStack.AddAddress(nicID, arp.ProtocolNumber, arp.ProtocolAddress)
		if err2 != nil {
			return 0, nil, fmt.Errorf("failed to add arp address: %s", err2.String())
		}
	}

	var routes []tcpip.Route
	if c.ProtocolStack.Networks.IPv4.Enabled {
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		})
	}

	if c.ProtocolStack.Networks.IPv6.Enabled {
		routes = append(routes, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		})
	}

	netStack.SetRouteTable(routes)

	return nicID, ep, nil
}

func (c Config) resolveProtocols() []stack.TransportProtocolFactory {
	var ret []stack.TransportProtocolFactory
	if c.ProtocolStack.Protocols.TCP.Enabled {
		ret = append(ret, tcp.NewProtocol)
	}
	if c.ProtocolStack.Protocols.UDP.Enabled {
		ret = append(ret, udp.NewProtocol)
	}

	if c.ProtocolStack.Protocols.ICMP.Enabled {
		if c.ProtocolStack.Networks.IPv4.Enabled {
			ret = append(ret, icmp.NewProtocol4)
		}

		if c.ProtocolStack.Networks.IPv6.Enabled {
			ret = append(ret, icmp.NewProtocol6)
		}
	}

	return ret
}

func (c StackConfig) configureProtocols(netStack *stack.Stack) error {
	err := c.Protocols.Raw.configure(netStack)
	if err != nil {
		return err
	}

	err = c.Protocols.ICMP.configure(netStack)
	if err != nil {
		return err
	}

	err = c.Protocols.TCP.configure(netStack)
	if err != nil {
		return err
	}

	err = c.Protocols.UDP.configure(netStack)
	if err != nil {
		return err
	}

	return nil
}

type StackNetworks struct {
	ARP  StackARPConfig  `json:"arp" yaml:"arp"`
	IPv4 StackIPv4Config `json:"ipv4" yaml:"ipv4"`
	IPv6 StackIPv6Config `json:"ipv6" yaml:"ipv6"`
}

type StackARPConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// nolint:unparam
func (c StackARPConfig) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	_ = netStack
	// err := netStack.SetForwarding(arp.ProtocolNumber, true)
	// if err != nil {
	// 	return fmt.Errorf("failed to enable arp forwarding: %s", err.String())
	// }

	return nil
}

type StackIPv4Config struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

func (c StackIPv4Config) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	err := netStack.SetForwarding(ipv4.ProtocolNumber, true)
	if err != nil {
		return fmt.Errorf("failed to enable ipv4 forwarding: %s", err.String())
	}
	return nil
}

type StackIPv6Config struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

func (c StackIPv6Config) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	err := netStack.SetForwarding(ipv6.ProtocolNumber, true)
	if err != nil {
		return fmt.Errorf("failed to enabled ipv6 forwarding: %s", err.String())
	}
	return nil
}

// nolint:maligned
type StackProtocols struct {
	// Raw socket support
	Raw StackRawConfig `json:"raw" yaml:"raw"`

	// ICMP support
	ICMP StackICMPConfig `json:"icmp" yaml:"icmp"`

	// TCP socket support
	TCP StackTCPConfig `json:"tcp" yaml:"tcp"`

	// UDP socket support
	UDP StackUDPConfig `json:"udp" yaml:"udp"`
}

type StackRawConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

func (c StackRawConfig) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	_ = netStack
	return nil
}

type StackICMPConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

func (c StackICMPConfig) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	_ = netStack
	return nil
}

type StackTCPConfig struct {
	Enabled bool          `json:"enabled" yaml:"enabled"`
	SAck    bool          `json:"sack" yaml:"sack"`
	NoDelay bool          `json:"nodelay" yaml:"nodelay"`
	Linger  time.Duration `json:"linger" yaml:"linger"`

	CongestionControlAlgorithms []string `json:"congestionControlAlgorithms" yaml:"congestionControlAlgorithms"`

	Buffer SendRecvBufferConfig `json:"buffer" yaml:"buffer"`
}

func (c StackTCPConfig) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	// enable buffer size auto-tuning
	opt := tcpip.TCPModerateReceiveBufferOption(true)
	err := netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
	if err != nil {
		return fmt.Errorf("failed to configure moderate recv buf: %s", err.String())
	}

	err = netStack.SetTransportProtocolOption(tcp.ProtocolNumber, c.Buffer.Recv.resolveTCPRecvBufOption())
	if err != nil {
		return fmt.Errorf("failed to configure recv buf: %s", err.String())
	}

	err = netStack.SetTransportProtocolOption(tcp.ProtocolNumber, c.Buffer.Send.resolveTCPSendBufOption())
	if err != nil {
		return fmt.Errorf("failed to configure send buf: %s", err.String())
	}

	tcpSACK := tcpip.TCPSACKEnabled(true)
	if !c.SAck {
		tcpSACK = false
	}
	err = netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSACK)
	if err != nil {
		return fmt.Errorf("failed to configure tcp sack: %s", err.String())
	}

	tcpDelay := tcpip.TCPDelayEnabled(false)
	if !c.NoDelay {
		tcpDelay = true
	}
	err = netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpDelay)
	if err != nil {
		return fmt.Errorf("failed to configure tcp nodelay: %s", err.String())
	}

	if c.Linger != 0 {
		tcpLinger := tcpip.TCPLingerTimeoutOption(c.Linger)
		err = netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpLinger)
		if err != nil {
			return fmt.Errorf("failed to configure tcp linger: %s", err.String())
		}
	}

	if len(c.CongestionControlAlgorithms) != 0 {
		ccAlgos := tcpip.TCPAvailableCongestionControlOption(strings.Join(c.CongestionControlAlgorithms, " "))
		err = netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &ccAlgos)
		if err != nil {
			return fmt.Errorf("failed to configure tcp congestion control algorithms: %s", err.String())
		}
	}

	return nil
}

type StackUDPConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

func (c StackUDPConfig) configure(netStack *stack.Stack) error {
	if !c.Enabled {
		return nil
	}

	_ = netStack
	return nil
}

type SendRecvBufferConfig struct {
	Send BufferConfig `json:"send" yaml:"send"`
	Recv BufferConfig `json:"recv" yaml:"recv"`
}

type BufferConfig struct {
	Min     int `json:"min" yaml:"min"`
	Max     int `json:"max" yaml:"max"`
	Default int `json:"default" yaml:"default"`
}

func (c BufferConfig) resolveTCPSendBufOption() *tcpip.TCPSendBufferSizeRangeOption {
	min, def, max := c.Min, c.Default, c.Max
	if min == 0 {
		min = 1
	}

	if max == 0 {
		max = min
	}

	if def == 0 {
		def = max
	}

	return &tcpip.TCPSendBufferSizeRangeOption{
		Min:     min,
		Default: def,
		Max:     max,
	}
}

func (c BufferConfig) resolveTCPRecvBufOption() *tcpip.TCPReceiveBufferSizeRangeOption {
	min, def, max := c.Min, c.Default, c.Max
	if min == 0 {
		min = 1
	}

	if max == 0 {
		max = min
	}

	if def == 0 {
		def = max
	}

	return &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     min,
		Default: def,
		Max:     max,
	}
}
