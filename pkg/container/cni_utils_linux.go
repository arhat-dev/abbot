package container

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"arhat.dev/abbot-proto/abbotgopb"
	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"arhat.dev/abbot/pkg/util"
)

type ConfigSnapshot struct {
	PID              uint32 `json:"pid" yaml:"pid"`
	EnsureRequest    string `json:"ensureRequest" yaml:"ensureRequest"`
	CNINetworkConfig string `json:"cniNetworkConfig" yaml:"cniNetworkConfig"`
}

func newContainerNetworkConfigSnapshot(
	req *abbotgopb.ContainerNetworkEnsureRequest, cniNetworkConfig string,
) (*ConfigSnapshot, error) {
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal container network ensure request: %w", err)
	}

	return &ConfigSnapshot{
		PID:              req.Pid,
		EnsureRequest:    base64.StdEncoding.EncodeToString(reqBytes),
		CNINetworkConfig: cniNetworkConfig,
	}, nil
}

func (m *Manager) getContainerNetworkConfigFile(containerID string) string {
	return filepath.Join(m.cniDataDir, fmt.Sprintf("%s.json", containerID))
}

func (m *Manager) cacheCNINetworkConfig(c *libcni.NetworkConfigList, configBytes []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cniNetworkConfig = c
	m.cniNetworkConfigBytes = configBytes
}

func (m *Manager) getCachedCNINetworkConfig() (*libcni.NetworkConfigList, []byte) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.cniNetworkConfig, m.cniNetworkConfigBytes
}

func (m *Manager) checkContainerNetworkInterfaces(
	pid uint32, containerID string,
) (uint32, []*abbotgopb.NetworkInterface, error) {
	if pid == 0 {
		if containerID == "" {
			return 0, nil, fmt.Errorf("no container id or pid provided")
		}

		var oldReq *abbotgopb.ContainerNetworkEnsureRequest
		oldReq, _, err := m.getContainerNetworkConfigSnapshot(containerID)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to lookup pid from containe network config snapshot: %w", err)
		}

		pid = oldReq.Pid
	}

	var ret []*abbotgopb.NetworkInterface
	err := util.DoInNetworkNamespace(pid, func() error {
		ifaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to check interfaces: %w", err)
		}

		for _, iface := range ifaces {
			ips, err := util.GetInterfaceIPs(iface.Name)
			if err != nil {
				return fmt.Errorf("failed to get interface addresses: %w", err)
			}

			var ipAddrs []string
			for _, ip := range ips {
				ipAddrs = append(ipAddrs, ip.String())
			}

			ret = append(ret, &abbotgopb.NetworkInterface{
				Name:            iface.Name,
				Addresses:       ipAddrs,
				HardwareAddress: iface.HardwareAddr.String(),
			})
		}

		return nil
	})

	if err != nil {
		return pid, nil, err
	}

	return pid, ret, nil
}

func (m *Manager) getContainerNetworkConfigSnapshot(
	containerID string,
) (*abbotgopb.ContainerNetworkEnsureRequest, []byte, error) {
	configFile := m.getContainerNetworkConfigFile(containerID)
	configBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load old config %s for container network: %w", configFile, err)
	}

	existingConfig := new(ConfigSnapshot)
	err = json.Unmarshal(configBytes, existingConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid old container network config %s: %w", configFile, err)
	}

	reqBytes, err := base64.StdEncoding.DecodeString(existingConfig.EnsureRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to delete old container network ensure request: %w", err)
	}

	req := new(abbotgopb.ContainerNetworkEnsureRequest)
	err = req.Unmarshal(reqBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal old container network ensure request: %w", err)
	}

	return req, []byte(existingConfig.CNINetworkConfig), nil
}

func (m *Manager) deleteContainerNetworks(
	ctx context.Context,
	netConfig *libcni.NetworkConfigList,
	rtConfig *libcni.RuntimeConf,
) error {
	if netConfig == nil {
		return fmt.Errorf("no cni network configured")
	}

	cniConfig := m.newCNIConfig()

	m.logger.V("deleting custom network")
	err := cniConfig.DelNetworkList(ctx, netConfig, rtConfig)
	if err != nil {
		return fmt.Errorf("failed to delete custom network: %w", err)
	}

	m.logger.V("deleting lookback network")
	err = cniConfig.DelNetworkList(ctx, m.cniLoopbackConfig, rtConfig)
	if err != nil {
		return fmt.Errorf("failed to delete loopback: %w", err)
	}

	return nil
}

func (m *Manager) addContainerNetworks(
	ctx context.Context,
	netConfig *libcni.NetworkConfigList,
	rtConfig *libcni.RuntimeConf,
) (_ []*abbotgopb.NetworkInterface, err error) {
	if netConfig == nil {
		return nil, fmt.Errorf("no cni network configured")
	}

	cniConfig := m.newCNIConfig()
	m.logger.V("adding lookback network")
	result, err := cniConfig.AddNetworkList(ctx, m.cniLoopbackConfig, rtConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to add required loopback: %w", err)
	}

	defer func() {
		if err != nil {
			err2 := cniConfig.DelNetworkList(ctx, m.cniLoopbackConfig, rtConfig)
			// TODO: log error
			_ = err2
		}
	}()

	if err = checkLoopbackResult(result); err != nil {
		return nil, fmt.Errorf("invalid loopback interface: %w", err)
	}

	m.logger.V("adding custom network")

	result, err = cniConfig.AddNetworkList(ctx, netConfig, rtConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to add custom network: %w", err)
	}

	defer func() {
		if err != nil {
			err2 := cniConfig.DelNetworkList(ctx, netConfig, rtConfig)
			// TODO: log error
			_ = err2
		}
	}()

	ret, err := checkCustomNetworkResult(result)
	if err != nil {
		return nil, fmt.Errorf("invalid custom network: %w", err)
	}

	return ret, nil
}

func checkLoopbackResult(result types.Result) error {
	r, err := current.NewResultFromResult(result)
	if err != nil {
		return fmt.Errorf("failed to resolve cni result for loopback: %w", err)
	}

	ifaces := r.Interfaces
	if len(ifaces) != 1 {
		return fmt.Errorf("unexpected count of loopback interface: %d", len(ifaces))
	}

	lo := ifaces[0]
	if lo.Name != "lo" {
		return fmt.Errorf("unexpected name of loopback interface: %s", lo.Name)
	}

	for _, ip := range r.IPs {
		if !ip.Address.IP.IsLoopback() {
			return fmt.Errorf("unexpected non loopback address: %s", ip.Address.String())
		}
	}

	return nil
}

func checkCustomNetworkResult(result types.Result) ([]*abbotgopb.NetworkInterface, error) {
	r, err := current.NewResultFromResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve cni result for custom network: %w", err)
	}

	var ret []*abbotgopb.NetworkInterface
	for i, iface := range r.Interfaces {
		var addrs []string
		for _, ip := range r.IPs {
			if ip.Interface == nil {
				continue
			}

			if *ip.Interface != i {
				addrs = append(addrs, ip.Address.String())
			}
		}

		ret = append(ret, &abbotgopb.NetworkInterface{
			Name:            iface.Name,
			Addresses:       addrs,
			HardwareAddress: iface.Mac,
		})
	}

	return ret, nil
}

func checkEnsureReqEqual(oldReq, req *abbotgopb.ContainerNetworkEnsureRequest) bool {
	if len(oldReq.CapArgs) != len(req.CapArgs) {
		return false
	}

	if len(oldReq.CniArgs) != len(req.CniArgs) {
		return false
	}

	for k, v := range req.CniArgs {
		oldV, ok := oldReq.CniArgs[k]
		if !ok {
			return false
		}

		if v != oldV {
			return false
		}
	}

	expectedCapArgs := createCompareMap(req.CapArgs)
	actualCapArgs := createCompareMap(oldReq.CapArgs)

	for a := range actualCapArgs {
		delete(expectedCapArgs, a)
	}

	return len(expectedCapArgs) == 0
}

func createCompareMap(capArgs []*abbotgopb.CNICapArgs) map[string]struct{} {
	var (
		args = make(map[string]struct{})
	)

	for _, arg := range capArgs {
		if ba := arg.GetBandwidthArg(); ba != nil {
			args[ba.String()] = struct{}{}
		}

		if maa := arg.GetMacAddressArg(); maa != nil {
			args[maa.String()] = struct{}{}
		}

		if ira := arg.GetIpRangeArg(); ira != nil {
			args[ira.String()] = struct{}{}
		}

		if iaa := arg.GetIpAddressesArg(); iaa != nil {
			args[iaa.String()] = struct{}{}
		}

		if ibga := arg.GetInfinibandGuidArg(); ibga != nil {
			args[ibga.String()] = struct{}{}
		}

		if dca := arg.GetDnsConfigArg(); dca != nil {
			args[dca.String()] = struct{}{}
		}
		if da := arg.GetDeviceIdArg(); da != nil {
			args[da.String()] = struct{}{}
		}

		if pma := arg.GetPortMapArg(); pma != nil {
			args[pma.String()] = struct{}{}
		}
	}

	return args
}

func (m *Manager) createCNIRuntimeConfig(req *abbotgopb.ContainerNetworkEnsureRequest) *libcni.RuntimeConf {
	var cniArgs [][2]string
	for k, v := range req.CniArgs {
		cniArgs = append(cniArgs, [2]string{k, v})
	}

	return &libcni.RuntimeConf{
		ContainerID: req.ContainerId,
		NetNS:       netnsPath(req.Pid),
		IfName:      m.containerDev,

		Args:           cniArgs,
		CapabilityArgs: getCapArgs(req.CapArgs),
	}
}

func (m *Manager) newCNIConfig() *libcni.CNIConfig {
	return libcni.NewCNIConfig(m.cniLookupPaths, &invoke.DefaultExec{
		RawExec:       &invoke.RawExec{Stderr: os.Stderr},
		PluginDecoder: version.PluginDecoder{},
	})
}

func netnsPath(pid uint32) string {
	return fmt.Sprintf("/proc/%d/ns/net", pid)
}

func getCapArgs(capArgs []*abbotgopb.CNICapArgs) map[string]interface{} {
	var (
		portMappings []*abbotgopb.CNICapArgs_PortMap
		ipRanges     [][]*abbotgopb.CNICapArgs_IPRange
	)

	result := make(map[string]interface{})
	for _, a := range capArgs {
		switch arg := a.Option.(type) {
		case *abbotgopb.CNICapArgs_IpRangeArg:
			ipRanges = append(ipRanges, []*abbotgopb.CNICapArgs_IPRange{arg.IpRangeArg})
		case *abbotgopb.CNICapArgs_PortMapArg:
			portMappings = append(portMappings, arg.PortMapArg)
		case *abbotgopb.CNICapArgs_BandwidthArg:
			result["bandwidth"] = arg.BandwidthArg
		case *abbotgopb.CNICapArgs_DnsConfigArg:
			result["dns"] = arg.DnsConfigArg
		case *abbotgopb.CNICapArgs_MacAddressArg:
			result["mac"] = arg.MacAddressArg
		case *abbotgopb.CNICapArgs_IpAddressesArg:
			result["ips"] = arg.IpAddressesArg
		case *abbotgopb.CNICapArgs_InfinibandGuidArg:
			result["infiniband_guid"] = arg.InfinibandGuidArg
		case *abbotgopb.CNICapArgs_DeviceIdArg:
			result["device_id"] = arg.DeviceIdArg
		}
	}

	if len(portMappings) != 0 {
		result["portMappings"] = portMappings
	}

	if len(ipRanges) != 0 {
		result["ipRanges"] = ipRanges
	}

	return result
}
