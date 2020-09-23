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

# native
abbot:
	sh scripts/build/build.sh $@

# linux
abbot.linux.x86:
	sh scripts/build/build.sh $@

abbot.linux.amd64:
	sh scripts/build/build.sh $@

abbot.linux.armv5:
	sh scripts/build/build.sh $@

abbot.linux.armv6:
	sh scripts/build/build.sh $@

abbot.linux.armv7:
	sh scripts/build/build.sh $@

abbot.linux.arm64:
	sh scripts/build/build.sh $@

abbot.linux.mips:
	sh scripts/build/build.sh $@

abbot.linux.mipshf:
	sh scripts/build/build.sh $@

abbot.linux.mipsle:
	sh scripts/build/build.sh $@

abbot.linux.mipslehf:
	sh scripts/build/build.sh $@

abbot.linux.mips64:
	sh scripts/build/build.sh $@

abbot.linux.mips64hf:
	sh scripts/build/build.sh $@

abbot.linux.mips64le:
	sh scripts/build/build.sh $@

abbot.linux.mips64lehf:
	sh scripts/build/build.sh $@

abbot.linux.ppc64:
	sh scripts/build/build.sh $@

abbot.linux.ppc64le:
	sh scripts/build/build.sh $@

abbot.linux.s390x:
	sh scripts/build/build.sh $@

abbot.linux.riscv64:
	sh scripts/build/build.sh $@

abbot.linux.all: \
	abbot.linux.x86 \
	abbot.linux.amd64 \
	abbot.linux.armv5 \
	abbot.linux.armv6 \
	abbot.linux.armv7 \
	abbot.linux.arm64 \
	abbot.linux.mips \
	abbot.linux.mipshf \
	abbot.linux.mipsle \
	abbot.linux.mipslehf \
	abbot.linux.mips64 \
	abbot.linux.mips64hf \
	abbot.linux.mips64le \
	abbot.linux.mips64lehf \
	abbot.linux.ppc64 \
	abbot.linux.ppc64le \
	abbot.linux.s390x \
	abbot.linux.riscv64

abbot.darwin.amd64:
	sh scripts/build/build.sh $@

# # currently darwin/arm64 build will fail due to golang link error
# abbot.darwin.arm64:
# 	sh scripts/build/build.sh $@

abbot.darwin.all: \
	abbot.darwin.amd64

abbot.windows.x86:
	sh scripts/build/build.sh $@

abbot.windows.amd64:
	sh scripts/build/build.sh $@

abbot.windows.armv5:
	sh scripts/build/build.sh $@

abbot.windows.armv6:
	sh scripts/build/build.sh $@

abbot.windows.armv7:
	sh scripts/build/build.sh $@

# # currently no support for windows/arm64
# abbot.windows.arm64:
# 	sh scripts/build/build.sh $@

abbot.windows.all: \
	abbot.windows.x86 \
	abbot.windows.amd64 \
	abbot.windows.armv7 \
	abbot.windows.armv6 \
	abbot.windows.armv5

# # android build requires android sdk
# abbot.android.amd64:
# 	sh scripts/build/build.sh $@

# abbot.android.x86:
# 	sh scripts/build/build.sh $@

# abbot.android.armv5:
# 	sh scripts/build/build.sh $@

# abbot.android.armv6:
# 	sh scripts/build/build.sh $@

# abbot.android.armv7:
# 	sh scripts/build/build.sh $@

# abbot.android.arm64:
# 	sh scripts/build/build.sh $@

# abbot.android.all: \
# 	abbot.android.amd64 \
# 	abbot.android.arm64 \
# 	abbot.android.x86 \
# 	abbot.android.armv7 \
# 	abbot.android.armv5 \
# 	abbot.android.armv6

abbot.freebsd.amd64:
	sh scripts/build/build.sh $@

abbot.freebsd.x86:
	sh scripts/build/build.sh $@

abbot.freebsd.armv5:
	sh scripts/build/build.sh $@

abbot.freebsd.armv6:
	sh scripts/build/build.sh $@

abbot.freebsd.armv7:
	sh scripts/build/build.sh $@

abbot.freebsd.arm64:
	sh scripts/build/build.sh $@

abbot.freebsd.all: \
	abbot.freebsd.amd64 \
	abbot.freebsd.arm64 \
	abbot.freebsd.armv7 \
	abbot.freebsd.x86 \
	abbot.freebsd.armv5 \
	abbot.freebsd.armv6

abbot.netbsd.amd64:
	sh scripts/build/build.sh $@

abbot.netbsd.x86:
	sh scripts/build/build.sh $@

abbot.netbsd.armv5:
	sh scripts/build/build.sh $@

abbot.netbsd.armv6:
	sh scripts/build/build.sh $@

abbot.netbsd.armv7:
	sh scripts/build/build.sh $@

abbot.netbsd.arm64:
	sh scripts/build/build.sh $@

abbot.netbsd.all: \
	abbot.netbsd.amd64 \
	abbot.netbsd.arm64 \
	abbot.netbsd.armv7 \
	abbot.netbsd.x86 \
	abbot.netbsd.armv5 \
	abbot.netbsd.armv6

abbot.openbsd.amd64:
	sh scripts/build/build.sh $@

abbot.openbsd.x86:
	sh scripts/build/build.sh $@

abbot.openbsd.armv5:
	sh scripts/build/build.sh $@

abbot.openbsd.armv6:
	sh scripts/build/build.sh $@

abbot.openbsd.armv7:
	sh scripts/build/build.sh $@

abbot.openbsd.arm64:
	sh scripts/build/build.sh $@

abbot.openbsd.all: \
	abbot.openbsd.amd64 \
	abbot.openbsd.arm64 \
	abbot.openbsd.armv7 \
	abbot.openbsd.x86 \
	abbot.openbsd.armv5 \
	abbot.openbsd.armv6

abbot.solaris.amd64:
	sh scripts/build/build.sh $@

abbot.aix.ppc64:
	sh scripts/build/build.sh $@

abbot.dragonfly.amd64:
	sh scripts/build/build.sh $@

abbot.plan9.amd64:
	sh scripts/build/build.sh $@

abbot.plan9.x86:
	sh scripts/build/build.sh $@

abbot.plan9.armv5:
	sh scripts/build/build.sh $@

abbot.plan9.armv6:
	sh scripts/build/build.sh $@

abbot.plan9.armv7:
	sh scripts/build/build.sh $@

abbot.plan9.all: \
	abbot.plan9.amd64 \
	abbot.plan9.armv7 \
	abbot.plan9.x86 \
	abbot.plan9.armv5 \
	abbot.plan9.armv6
