package conf

type HostNetworkConfig struct {
	Interfaces []InterfaceConfig `json:"interfaces" yaml:"interfaces"`
	// Proxies config to redirect network traffic
	Proxies []ProxyConfig `json:"proxies" yaml:"proxies"`
}
