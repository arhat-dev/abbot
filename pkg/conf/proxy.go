package conf

type ProxyConfig struct {
	// Address the address of the proxy server
	Address string `json:"address" yaml:"address"`

	// Protocols to be proxied, will proxy all if not set
	Protocols []string `json:"protocols" yaml:"protocols"`

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
