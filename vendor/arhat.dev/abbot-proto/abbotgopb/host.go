package abbotgopb

func NewHostNetworkInterface(
	name string,
	mtu int32,
	hardwareAddress string,
	addresses []string,
	config interface{},
) *HostNetworkInterface {
	var cfg isHostNetworkInterface_Config
	switch c := config.(type) {
	case *DriverBridge:
		cfg = &HostNetworkInterface_Bridge{
			Bridge: c,
		}
	case *DriverWireguard:
		cfg = &HostNetworkInterface_Wireguard{
			Wireguard: c,
		}
	default:
		cfg = &HostNetworkInterface_Unknown{
			Unknown: &DriverUnknown{},
		}
	}

	return &HostNetworkInterface{
		Metadata: &NetworkInterface{
			Name:            name,
			Mtu:             mtu,
			HardwareAddress: hardwareAddress,
			Addresses:       addresses,
		},
		Config: cfg,
	}
}
