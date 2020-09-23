package conf

type ProxyConfig struct {
	// AddressV4 the ipv4 address of the proxy server
	AddressV4 string `json:"addr4" yaml:"addr4"`

	// AddressV6 the ipv6 address of the proxy server
	AddressV6 string `json:"addr6" yaml:"addr6"`

	// IPRanges to be redirect through this proxy
	IPRanges []string `json:"ipRanges" yaml:"ipRanges"`

	// Tproxy the transparent proxy, only works on linux
	Tproxy TProxyConfig `json:"tproxy" yaml:"tproxy"`
}

// Linux specific config options
type (
	TProxyRoutingConfig struct {
		// routing rule priority for tproxy fwmark routing
		RulePriority int `json:"rulePriority" yaml:"rulePriority"`
		// routing table for tproxy fwmark lookup, 1 - 255
		Table int `json:"table" yaml:"table"`
	}

	TProxyConfig struct {
		// fwmark in netfilter and routing rule in the form `<mark>[/<mask>]`
		Mark string `json:"mark" yaml:"mark"`
		TCP  bool   `json:"tcp" yaml:"tcp"`
		UDP  bool   `json:"udp" yaml:"udp"`

		Routing TProxyRoutingConfig `json:"routing" yaml:"routing"`
	}
)
