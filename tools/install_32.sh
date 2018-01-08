#!/bin/sh

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root"
	exit 1
fi

echo "[+] Adding 32-bit architecture..."
dpkg --add-architecture i386
if [ $? -ne 0 ]; then
	echo "[!] Error: Unable to add 32-bit architecture."
	exit 1
fi

echo "[+] Updating sources..."
apt-get update

echo "[+] Installing 32-bit libraries..."
apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
if [ $? -ne 0 ]; then
	echo "[!] Error: Failed to install 32-bit libraries."
	exit 1
fi
