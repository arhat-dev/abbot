module arhat.dev/abbot

go 1.15

// currently only this version of gvisor works
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20201001012933-c4f3063255be

require (
	arhat.dev/abbot-proto v0.1.1-0.20201127100340-fcd4ba56957a
	arhat.dev/pkg v0.4.4
	github.com/containernetworking/cni v0.8.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/goiiot/libmqtt v0.9.6
	github.com/klauspost/compress v1.11.1 // indirect
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	go.uber.org/multierr v1.6.0
	golang.org/x/sys v0.0.0-20201126233918-771906719818
	golang.zx2c4.com/wireguard v0.0.20201118
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200609130330-bd2cb7843e1b
	golang.zx2c4.com/wireguard/windows v0.3.1
	google.golang.org/grpc v1.33.2
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
	gvisor.dev/gvisor v0.0.0-20201001012933-c4f3063255be
)

replace (
	k8s.io/api => github.com/kubernetes/api v0.19.4
	k8s.io/apiextensions-apiserver => github.com/kubernetes/apiextensions-apiserver v0.19.4
	k8s.io/apimachinery => github.com/kubernetes/apimachinery v0.19.4
	k8s.io/apiserver => github.com/kubernetes/apiserver v0.19.4
	k8s.io/cli-runtime => github.com/kubernetes/cli-runtime v0.19.4
	k8s.io/client-go => github.com/kubernetes/client-go v0.19.4
	k8s.io/cloud-provider => github.com/kubernetes/cloud-provider v0.19.4
	k8s.io/cluster-bootstrap => github.com/kubernetes/cluster-bootstrap v0.19.4
	k8s.io/code-generator => github.com/kubernetes/code-generator v0.19.4
	k8s.io/component-base => github.com/kubernetes/component-base v0.19.4
	k8s.io/cri-api => github.com/kubernetes/cri-api v0.19.4
	k8s.io/csi-translation-lib => github.com/kubernetes/csi-translation-lib v0.19.4
	k8s.io/klog => github.com/kubernetes/klog v1.0.0
	k8s.io/klog/v2 => github.com/kubernetes/klog/v2 v2.4.0
	k8s.io/kube-aggregator => github.com/kubernetes/kube-aggregator v0.19.4
	k8s.io/kube-controller-manager => github.com/kubernetes/kube-controller-manager v0.19.4
	k8s.io/kube-proxy => github.com/kubernetes/kube-proxy v0.19.4
	k8s.io/kube-scheduler => github.com/kubernetes/kube-scheduler v0.19.4
	k8s.io/kubectl => github.com/kubernetes/kubectl v0.19.4
	k8s.io/kubelet => github.com/kubernetes/kubelet v0.19.4
	k8s.io/kubernetes => github.com/kubernetes/kubernetes v1.19.4
	k8s.io/legacy-cloud-providers => github.com/kubernetes/legacy-cloud-providers v0.19.4
	k8s.io/metrics => github.com/kubernetes/metrics v0.19.4
	k8s.io/sample-apiserver => github.com/kubernetes/sample-apiserver v0.19.4
	k8s.io/utils => github.com/kubernetes/utils v0.0.0-20201110183641-67b214c5f920
	vbom.ml/util => github.com/fvbommel/util v0.0.2
)
