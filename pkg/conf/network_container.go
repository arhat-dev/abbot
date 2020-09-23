package conf

type CNINetworkConfig struct {
	ContainerDevice string `json:"containerDev" yaml:"containerDev"`
	Template        string `json:"template" yaml:"template"`
}

type ContainerNetworkConfig struct {
	// DataDir to store pod container network config
	DataDir        string   `json:"dataDir" yaml:"dataDir"`
	CNILookupPaths []string `json:"cniLookupPaths" yaml:"cniLookupPaths"`

	Networks []CNINetworkConfig `json:"networks" yaml:"networks"`
}
