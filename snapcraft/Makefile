#
# Copyright (C) 2016 Canonical
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

#
# Simple makefile to mangle version info in the yaml file
#
VERSION=$(shell git tag | tail -1 | cut -c2-)
COMMITS=$(shell git log --oneline | wc -l)
SHA=$(shell git log -1 --oneline | cut -d' ' -f1)
DATE=$(shell date +'%Y%m%d')
V=$(VERSION)-$(DATE)-$(COMMITS)-$(SHA)

all: set_version
	snapcraft

set_version:
	cat snapcraft.yaml | sed 's/version: .*/version: $(V)/' > snapcraft-tmp.yaml
	mv snapcraft-tmp.yaml snapcraft.yaml

install:
	#
	# Install latest snap
	#
	sudo snap install --devmode bcc_*.snap

	#
	# Connect up interfaces
	#
	sudo snap connect bcc:mount-observe
	sudo snap connect bcc:system-observe
	sudo snap connect bcc:system-trace

remove:
	sudo snap remove bcc

clean:
	snapcraft clean
	rm -rf setup *.snap snapcraft
