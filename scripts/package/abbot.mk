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

#
# linux
#
package.abbot.deb.amd64:
	sh scripts/package/package.sh $@

package.abbot.deb.armv6:
	sh scripts/package/package.sh $@

package.abbot.deb.armv7:
	sh scripts/package/package.sh $@

package.abbot.deb.arm64:
	sh scripts/package/package.sh $@

package.abbot.deb.all: \
	package.abbot.deb.amd64 \
	package.abbot.deb.armv6 \
	package.abbot.deb.armv7 \
	package.abbot.deb.arm64

package.abbot.rpm.amd64:
	sh scripts/package/package.sh $@

package.abbot.rpm.armv7:
	sh scripts/package/package.sh $@

package.abbot.rpm.arm64:
	sh scripts/package/package.sh $@

package.abbot.rpm.all: \
	package.abbot.rpm.amd64 \
	package.abbot.rpm.armv7 \
	package.abbot.rpm.arm64

package.abbot.linux.all: \
	package.abbot.deb.all \
	package.abbot.rpm.all

#
# windows
#

package.abbot.msi.amd64:
	sh scripts/package/package.sh $@

package.abbot.msi.arm64:
	sh scripts/package/package.sh $@

package.abbot.msi.all: \
	package.abbot.msi.amd64 \
	package.abbot.msi.arm64

package.abbot.windows.all: \
	package.abbot.msi.all

#
# darwin
#

package.abbot.pkg.amd64:
	sh scripts/package/package.sh $@

package.abbot.pkg.arm64:
	sh scripts/package/package.sh $@

package.abbot.pkg.all: \
	package.abbot.pkg.amd64 \
	package.abbot.pkg.arm64

package.abbot.darwin.all: \
	package.abbot.pkg.all
