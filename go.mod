module arhat.dev/abbot

go 1.15

replace (
	k8s.io/api => github.com/kubernetes/api v0.18.8
	k8s.io/apiextensions-apiserver => github.com/kubernetes/apiextensions-apiserver v0.18.8
	k8s.io/apimachinery => github.com/kubernetes/apimachinery v0.18.8
	k8s.io/apiserver => github.com/kubernetes/apiserver v0.18.8
	k8s.io/cli-runtime => github.com/kubernetes/cli-runtime v0.18.8
	k8s.io/client-go => github.com/kubernetes/client-go v0.18.8
	k8s.io/cloud-provider => github.com/kubernetes/cloud-provider v0.18.8
	k8s.io/cluster-bootstrap => github.com/kubernetes/cluster-bootstrap v0.18.8
	k8s.io/code-generator => github.com/kubernetes/code-generator v0.18.8
	k8s.io/component-base => github.com/kubernetes/component-base v0.18.8
	k8s.io/cri-api => github.com/kubernetes/cri-api v0.18.8
	k8s.io/csi-translation-lib => github.com/kubernetes/csi-translation-lib v0.18.8
	k8s.io/klog => github.com/kubernetes/klog v1.0.0
	k8s.io/klog/v2 => github.com/kubernetes/klog/v2 v2.3.0
	k8s.io/kube-aggregator => github.com/kubernetes/kube-aggregator v0.18.8
	k8s.io/kube-controller-manager => github.com/kubernetes/kube-controller-manager v0.18.8
	k8s.io/kube-proxy => github.com/kubernetes/kube-proxy v0.18.8
	k8s.io/kube-scheduler => github.com/kubernetes/kube-scheduler v0.18.8
	k8s.io/kubectl => github.com/kubernetes/kubectl v0.18.8
	k8s.io/kubelet => github.com/kubernetes/kubelet v0.18.8
	k8s.io/kubernetes => github.com/kubernetes/kubernetes v1.18.8
	k8s.io/legacy-cloud-providers => github.com/kubernetes/legacy-cloud-providers v0.18.8
	k8s.io/metrics => github.com/kubernetes/metrics v0.18.8
	k8s.io/sample-apiserver => github.com/kubernetes/sample-apiserver v0.18.8
	k8s.io/utils => github.com/kubernetes/utils v0.0.0-20200821003339-5e75c0163111
	vbom.ml/util => github.com/fvbommel/util v0.0.2
)

// Temporary fix for darwin syscall
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200501145240-bc7a7d42d5c3

require (
	arhat.dev/abbot-proto v0.0.0-20200908152444-df59421a64d2
	arhat.dev/pkg v0.0.0-20200814094720-eac4d5d5680b
	github.com/containernetworking/cni v0.7.1
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20171111001504-be1fbeda1936
	go.uber.org/multierr v1.5.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a // indirect
	golang.org/x/net v0.0.0-20200904194848-62affa334b73 // indirect
	golang.org/x/sys v0.0.0-20200922070232-aee5d888a860 // indirect
	golang.org/x/text v0.3.3 // indirect
	golang.zx2c4.com/wireguard v0.0.20200320
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200609130330-bd2cb7843e1b
	google.golang.org/grpc v1.31.1
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/kubernetes v1.18.6
	k8s.io/utils v0.0.0-20200324210504-a9aa75ae1b89
)
