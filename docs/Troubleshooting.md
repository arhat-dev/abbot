# Troubleshooting

## Network issues

If you have deployed `abbot` and using cluster network for you containers, you may encounter some issues

### Container network not working

Possible Cause: The bridge netfilter not enabled
Solution: enable bridge netfilter before deploying containers

```bash
modprobe br_netfilter

sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.bridge.bridge-nf-call-ip6tables=1
```

### Bridge not forwarding traffic to outside network

Solution: enable traffic forwarding using sysctl

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
```

### Traffic to cluster not forwarded (not using tproxy)

Solution: enable traffic forwarding in local network

```bash
sysctl -w net.ipv4.conf.all.route_localnet=1
```

### `abbot` container deployment failure due to iptables failure

Solution: enable ip6table_filter

```bash
modprobe ip6table_mangle
modprobe ip6table_nat
```
