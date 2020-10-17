# abbot

`abbot` is a network manager for edge devices

## Introduction

This is the official helm chart for [abbot](https://github.com/arhat-dev/abbot), you can deploy `abbot` to your edge devices to create userspace network and vpn mesh

## Prerequisites

- `helm` v3
- `Kubernetes` 1.15+

## Installing the Chart

```bash
helm install my-release arhat-dev/abbot
```

## Uninstalling the Chart

```bash
helm delete my-release
```

## Configuration

Please refer to the [`values.yaml`](https://github.com/arhat-dev/abbot/blob/master/cicd/deploy/charts/abbot/values.yaml)
