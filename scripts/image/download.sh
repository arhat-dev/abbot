#!/bin/sh

# Copyright 2020 The arhat.dev Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

cni_plugins() {
  arch="$1"
  version="v0.8.7"

  case "${arch}" in
    armv*)
      arch=arm
    ;;
  esac

  wget -O /cni.tar.gz \
    https://github.com/containernetworking/plugins/releases/download/${version}/cni-plugins-linux-${arch}-${version}.tgz
  mkdir -p /opt/cni/bin
  tar xf /cni.tar.gz -C /opt/cni/bin
}

"$@"
