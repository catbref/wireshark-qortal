#!/usr/bin/env bash

# Build script to integrate qora plugin into wireshark FreeBSD port

# To be run as root in /usr/ports/net/wireshark
if [ "${UID}" != "0" -o "${PWD}" != "/usr/ports/net/wireshark" ]; then
	echo "Must be run as root in /usr/ports/net/wireshark"
	exit 1
fi

# SRC is directory containing this script, cmake files and packet-qora.c
SRC=$(dirname $(realpath "$0"))

DST=work/wireshark-3.0.3
DST_QORA=${DST}/plugins/epan/qora

set -e

make clean

if patch --silent --force --dry-run pkg-plist ${SRC}/pkg-plist.diff 1>/dev/null 2>&1; then
	echo Patching pkg-plist to include plugin
	patch --silent --force pkg-plist ${SRC}/pkg-plist.diff
fi

if [ -d "/tmp/wireshark-build" ]; then
	echo Reusing partial build from /tmp
	cp -a /tmp/wireshark-build work
else
	echo Creating partial build in /tmp
	make extract

	cp ${SRC}/CMakeListsCustom.txt ${DST}/

	mkdir -p ${DST_QORA}
	cp ${SRC}/CMakeLists.txt ${DST_QORA}/
	echo 'FORCE COMPILE ERROR' > ${DST_QORA}/packet-qora.c

	make build || true

	echo Saving partial build into /tmp

	ln -sf ${SRC}/packet-qora.c ${DST_QORA}/packet-qora.c
	cp -a work /tmp/wireshark-build
fi

echo Building...
make build
