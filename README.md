# Abbot `住持`

[![CI](https://github.com/arhat-dev/abbot/workflows/CI/badge.svg)](https://github.com/arhat-dev/abbot/actions?query=workflow%3ACI)
[![Build](https://github.com/arhat-dev/abbot/workflows/Build/badge.svg)](https://github.com/arhat-dev/abbot/actions?query=workflow%3ABuild)
[![PkgGoDev](https://pkg.go.dev/badge/arhat.dev/abbot)](https://pkg.go.dev/arhat.dev/abbot)
[![GoReportCard](https://goreportcard.com/badge/arhat.dev/abbot)](https://goreportcard.com/report/arhat.dev/abbot)
[![codecov](https://codecov.io/gh/arhat-dev/abbot/branch/master/graph/badge.svg)](https://codecov.io/gh/arhat-dev/abbot)

Network manager living at edge

## Features

- [x] Host Network Management
  - Drivers
    - [ ] `wireguard` (linux)
    - [x] `wireguard` over `tun`(L3) devices (linux, windows, macos, freebsd, openbsd)
    - [x] `bridge` (linux)
    - [ ] (WIP) [`usernet`](./docs/Driver-usernet.md) (linux, aix, windows, macos, freebsd, openbsd, dragonfly, solaris, netbsd)
      - underlay network:
        - `gVisor` over `tun`
      - overlay network:
        - `mqtt`
- [x] Container Network Management

## Development

see [docs/Development.md](./docs/Development.md)

## LICENSE

```text
Copyright 2020 The arhat.dev Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
