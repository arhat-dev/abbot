# Development

## Implement custom drivers

1. Add driver config in [`abbot-proto`](https://github.com/arhat-dev/abbot-proto)
   - Define driver config in `src/driver_xxx.proto` (where `xxx` is your driver name in snake case), message name MUST be in `DriverXxx` format, where `Xxx` is your driver name in camel case, message field names MUST be in snake case.
   - Append your config to the `oneof` section of [src/host.proto#HostNetworkInterface](https://github.com/arhat-dev/abbot-proto/blob/master/src/host.proto).
   - Generate required files with `make gen.proto.all`.
   - Update the type switch cases in [abbotgopb/host.go](https://github.com/arhat-dev/abbot-proto/blob/master/abbotgopb/host.go) to include your config.
   - Commit and push your changes.

2. Update `go.mod` to use desiered [`abbot-proto`](https://github.com/arhat-dev/abbot-proto) with your new drvier config

3. Create a new directory [`pkg/drivers/xxx`](https://github.com/arhat-dev/abbot/blob/master/pkg/driver), where `xxx` is your driver name in snake case, and in this directory:
   - Create file `config.go`, define your config and config factory func like [wireguard/config.go](https://github.com/arhat-dev/abbot/blob/master/pkg/drivers/wireguard/config.go)
   - Implement your driver and driver factory in `xxx.go` (where `xxx` is your driver name in snake case), register your driver config factory and driver factory func in this file with driver name in snake case like [`wireguard/wireguard.go`](https://github.com/arhat-dev/abbot/blob/master/pkg/drivers/wireguard/wireguard.go)

4. Import your driver in [pkg/drivers/driveradd/add_xxx.go](https://github.com/arhat-dev/abbot/blob/master/pkg/drivers/driveradd) and restrict build tags to avoid unexpected build failure
