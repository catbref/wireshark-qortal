#!/usr/bin/env bash

# Build script to integrate Qortal plugin into wireshark FreeBSD port

# To be run as root in /usr/ports/net/wireshark
if [ "${UID}" != "0" -o "${PWD}" != "/usr/ports/net/wireshark" ]; then
	echo "Must be run as root in /usr/ports/net/wireshark"
	exit 1
fi

# SRC is directory containing this script, cmake files and packet-qortal.c
SRC=$(dirname $(realpath "$0"))

port_version=$( perl -n -e 'print $1 if m/^\s*PORTVERSION\W+(\S+)/' < Makefile )
DST=work/wireshark-${port_version}
DST_QORTAL=${DST}/plugins/epan/qortal

set -e

make clean

if fgrep --silent qortal pkg-plist; then
	:
else
	echo Patching pkg-plist to include plugin
	perl -p -i -e 'print "$1qortal.so\n" if m|^(lib/wireshark/plugins/.*?/epan/)gryphon.so|' pkg-plist
fi

if [ -d "/tmp/wireshark-build" ]; then
	echo Reusing partial build from /tmp
	cp -a /tmp/wireshark-build work
else
	echo Creating partial build in /tmp
	make extract

	cp ${SRC}/CMakeListsCustom.txt ${DST}/

	mkdir -p ${DST_QORTAL}
	cp ${SRC}/CMakeLists.txt ${DST_QORTAL}/
	echo 'FORCE COMPILE ERROR' > ${DST_QORTAL}/packet-qortal.c

	make build || true

	echo Saving partial build into /tmp

	ln -sf ${SRC}/packet-qortal.c ${DST_QORTAL}/packet-qortal.c
	cp -a work /tmp/wireshark-build
fi

echo Building...
make build
