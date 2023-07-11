#!/bin/bash

set -e

if [ ! -f /etc/resolv.conf.bak ]; then
    sudo mv /etc/resolv.conf /etc/resolv.conf.bak
    sudo ln -s /etc/resolvconf/run/resolv.conf /etc/resolv.conf
    sudo sed -i 's/^PLATFORM_VERSION=5$/PLATFORM_VERSION=5-fix-resolv.conf/g' /etc/lsb-release
    sudo sed -i 's/^PLATFORM_VERSION=5-fixed$/PLATFORM_VERSION=5-fix-resolv.conf/g' /etc/lsb-release
    echo 'fix_resolv_conf terminated'
else
	echo "resolv.conf already fixed on the platform!"
fi