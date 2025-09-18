#!/bin/bash
# setup-tools.sh
# Installer script for secure wipe environment on Bookworm Puppy Linux

set -e

echo "[*] Updating package list..."
sudo apt-get update -y

echo "[*] Installing core tools for device detection..."
sudo apt-get install -y \
    util-linux \
    blkid \
    smartmontools \
    gptfdisk \
    hdparm \
    nvme-cli \
    lshw \
    usbutils \
    pciutils

echo "[*] Installing wiping tools..."
sudo apt-get install -y \
    wipe \
    secure-delete \
    nwipe \
    shred \
    ddrescue

echo "[*] Installing JSON & certificate tools..."
sudo apt-get install -y \
    jq \
    openssl \
    python3 \
    python3-pip \
    ghostscript

echo "[*] Installing Python libraries for PDF certificate generation..."
pip3 install reportlab

echo "[*] All required tools installed successfully!"
echo "---------------------------------------------"
echo "Tools installed:"
echo "  - Detection: lsblk, blkid, smartctl, hdparm, nvme-cli, sgdisk"
echo "  - Wiping: shred, wipe, nwipe, secure-delete"
echo "  - Certificates: jq, openssl, python3, reportlab"
echo
echo "You are ready to run detection, wiping, and certificate scripts."


