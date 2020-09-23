package constant

const (
	TemplateLoopbackNetwork = `{
  "cniVersion": "0.3.1",
  "name": "cni-loopback",
  "plugins":[{
    "type": "loopback"
  }]
}`
	// nolint:lll
	TemplateContainerNetwork = `{
  "cniVersion": "0.3.1",
  "name": "abbot",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "{{ .HostDevice }}",
      "isGateway": true,
      "isDefaultGateway": true,
      "ipMasq": true,
      "forceAddress": true,
      "ipam": {
        "type": "host-local",
        "ranges": [{{ if gt (len .IPv4Subnet) 0 }}
          [{
            "subnet": "{{ .IPv4Subnet }}",
            "routes": [{ "dst": "0.0.0.0/0" }]
          }]{{ end }}{{ if and (gt (len .IPv6Subnet) 0) (gt (len .IPv4Subnet) 0) }},{{ end }}{{ if gt (len .IPv6Subnet) 0 }}
          [{
            "subnet": "{{ .IPv6Subnet }}"
          }]{{ end }}
        ]
      }
    },
    {
      "type": "portmap",
      "capabilities": { "portMappings": true }
    },
    {
      "type": "bandwidth",
      "capabilities": { "bandwidth": true }
    }
  ]
}`
)
