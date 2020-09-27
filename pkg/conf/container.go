package conf

type ContainerNetworkConfig struct {
	// DataDir to store pod container network config
	DataDir string `json:"dataDir" yaml:"dataDir"`

	CNIPluginsLookupPaths []string `json:"cniPluginsLookupPaths" yaml:"cniPluginsLookupPaths"`

	// InterfaceName in container
	ContainerInterfaceName string `json:"containerInterfaceName" yaml:"containerInterfaceName"`

	// Template of cni config
	Template string `json:"template" yaml:"template"`
}
