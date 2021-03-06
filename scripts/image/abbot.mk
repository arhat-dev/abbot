# Copyright 2020 The arhat.dev Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# build
image.build.abbot.linux.x86:
	sh scripts/image/build.sh $@

image.build.abbot.linux.amd64:
	sh scripts/image/build.sh $@

image.build.abbot.linux.armv5:
	sh scripts/image/build.sh $@

image.build.abbot.linux.armv6:
	sh scripts/image/build.sh $@

image.build.abbot.linux.armv7:
	sh scripts/image/build.sh $@

image.build.abbot.linux.arm64:
	sh scripts/image/build.sh $@

image.build.abbot.linux.ppc64le:
	sh scripts/image/build.sh $@

image.build.abbot.linux.mips64le:
	sh scripts/image/build.sh $@

image.build.abbot.linux.s390x:
	sh scripts/image/build.sh $@

image.build.abbot.linux.all: \
	image.build.abbot.linux.amd64 \
	image.build.abbot.linux.arm64 \
	image.build.abbot.linux.armv7 \
	image.build.abbot.linux.armv6 \
	image.build.abbot.linux.armv5 \
	image.build.abbot.linux.x86 \
	image.build.abbot.linux.s390x \
	image.build.abbot.linux.ppc64le \
	image.build.abbot.linux.mips64le

image.build.abbot.windows.amd64:
	sh scripts/image/build.sh $@

image.build.abbot.windows.armv7:
	sh scripts/image/build.sh $@

image.build.abbot.windows.all: \
	image.build.abbot.windows.amd64 \
	image.build.abbot.windows.armv7

# push
image.push.abbot.linux.x86:
	sh scripts/image/push.sh $@

image.push.abbot.linux.amd64:
	sh scripts/image/push.sh $@

image.push.abbot.linux.armv5:
	sh scripts/image/push.sh $@

image.push.abbot.linux.armv6:
	sh scripts/image/push.sh $@

image.push.abbot.linux.armv7:
	sh scripts/image/push.sh $@

image.push.abbot.linux.arm64:
	sh scripts/image/push.sh $@

image.push.abbot.linux.ppc64le:
	sh scripts/image/push.sh $@

image.push.abbot.linux.mips64le:
	sh scripts/image/push.sh $@

image.push.abbot.linux.s390x:
	sh scripts/image/push.sh $@

image.push.abbot.linux.all: \
	image.push.abbot.linux.amd64 \
	image.push.abbot.linux.arm64 \
	image.push.abbot.linux.armv7 \
	image.push.abbot.linux.armv6 \
	image.push.abbot.linux.armv5 \
	image.push.abbot.linux.x86 \
	image.push.abbot.linux.s390x \
	image.push.abbot.linux.ppc64le \
	image.push.abbot.linux.mips64le

image.push.abbot.windows.amd64:
	sh scripts/image/push.sh $@

image.push.abbot.windows.armv7:
	sh scripts/image/push.sh $@

image.push.abbot.windows.all: \
	image.push.abbot.windows.amd64 \
	image.push.abbot.windows.armv7
