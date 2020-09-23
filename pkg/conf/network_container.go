package conf

type CNINetworkConfig struct {
	ContainerDevice string `json:"containerDev" yaml:"containerDev"`
	Template        string `json:"template"`
}

type ContainerNetworkConfig struct {
	// DataDir to store pod container network config
	DataDir string `json:"dataDir" yaml:"dataDir"`

	// Proxies config to redirect network traffic to cluster
	Proxies []ProxyConfig `json:"proxies" yaml:"proxies"`

	CNILookupPaths []string `json:"cniLookupPaths" yaml:"cniLookupPaths"`

	Networks []CNINetworkConfig `json:"networks" yaml:"networks"`
}
