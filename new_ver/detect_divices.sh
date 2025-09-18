#!/bin/bash

# Device Detection Script for Secure Data Wiping
# Detects internal drives, OS drives, and external devices
# NIST SP 800-88 compliant device identification

set -e

# Global variables
SCRIPT_DIR="/tmp/secure_wipe"
LOG_FILE="/var/log/secure_wipe/detection.log"
DEVICE_INFO_FILE="$SCRIPT_DIR/detected_devices.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Initialize
initialize() {
    echo -e "${BLUE}=================================================="
    echo -e "Secure Data Wiping - Device Detection Module"
    echo -e "==================================================${NC}"
    
    # Create directories
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Clear previous detection results
    > "$LOG_FILE"
    > "$DEVICE_INFO_FILE"
    
    log_message "Device detection started"
    echo
}

# Get device type (HDD/SSD/NVMe/USB/etc.)
get_device_type() {
    local device=$1
    local device_type="Unknown"
    
    # Check if it's an NVMe device
    if [[ $device =~ nvme[0-9]+n[0-9]+ ]]; then
        device_type="NVMe SSD"
    # Check if it's rotational (HDD vs SSD)
    elif [ -f "/sys/block/$(basename $device)/queue/rotational" ]; then
        local rotational=$(cat "/sys/block/$(basename $device)/queue/rotational" 2>/dev/null)
        if [ "$rotational" = "1" ]; then
            device_type="HDD"
        else
            device_type="SSD"
        fi
    fi
    
    # Check if it's USB connected
    local usb_check=$(udevadm info --query=property --name="$device" 2>/dev/null | grep -i "ID_BUS=usb" || true)
    if [ -n "$usb_check" ]; then
        device_type="USB $device_type"
    fi
    
    echo "$device_type"
}

# Get device size in human readable format
get_device_size() {
    local device=$1
    local size_bytes=$(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ')
    
    if [ -n "$size_bytes" ] && [ "$size_bytes" -gt 0 ]; then
        echo "$size_bytes" | awk '{
            if ($1 >= 1099511627776) printf "%.2f TB", $1/1099511627776
            else if ($1 >= 1073741824) printf "%.2f GB", $1/1073741824
            else if ($1 >= 1048576) printf "%.2f MB", $1/1048576
            else printf "%d B", $1
        }'
    else
        echo "Unknown"
    fi
}

# Check if device contains OS
is_os_device() {
    local device=$1
    local is_os=false
    
    # Check if any partition is mounted as root or contains boot files
    local partitions=$(lsblk -ln -o NAME "$device" 2>/dev/null | grep -v "^$(basename $device)$" | sed 's/^[├└]─//')
    
    for partition in $partitions; do
        local mountpoint=$(lsblk -ln -o MOUNTPOINT "/dev/$partition" 2>/dev/null)
        if [[ "$mountpoint" == "/" ]] || [[ "$mountpoint" == "/boot"* ]]; then
            is_os=true
            break
        fi
        
        # Check if partition has boot flag or contains OS signatures
        local fstype=$(lsblk -ln -o FSTYPE "/dev/$partition" 2>/dev/null)
        if [[ "$fstype" == "ext4" ]] || [[ "$fstype" == "ext3" ]] || [[ "$fstype" == "ntfs" ]] || [[ "$fstype" == "fat32" ]]; then
            # Additional checks for OS presence could be added here
            local boot_check=$(file -s "/dev/$partition" 2>/dev/null | grep -i "boot" || true)
            if [ -n "$boot_check" ]; then
                is_os=true
                break
            fi
        fi
    done
    
    # Check if device itself is mounted as root
    local device_mount=$(lsblk -ln -o MOUNTPOINT "$device" 2>/dev/null)
    if [[ "$device_mount" == "/" ]]; then
        is_os=true
    fi
    
    echo "$is_os"
}

# Get SMART information
get_smart_info() {
    local device=$1
    local smart_info="Not Available"
    
    if command -v smartctl &> /dev/null; then
        local smart_output=$(smartctl -i "$device" 2>/dev/null || true)
        if [ -n "$smart_output" ]; then
            local model=$(echo "$smart_output" | grep "Device Model" | cut -d: -f2- | sed 's/^ *//')
            local serial=$(echo "$smart_output" | grep "Serial Number" | cut -d: -f2- | sed 's/^ *//')
            local firmware=$(echo "$smart_output" | grep "Firmware Version" | cut -d: -f2- | sed 's/^ *//')
            
            if [ -n "$model" ]; then
                smart_info="Model: $model"
                [ -n "$serial" ] && smart_info="$smart_info, S/N: $serial"
                [ -n "$firmware" ] && smart_info="$smart_info, FW: $firmware"
            fi
        fi
    fi
    
    echo "$smart_info"
}

# Detect encryption
detect_encryption() {
    local device=$1
    local encryption_status="None"
    
    # Check for LUKS encryption
    if command -v cryptsetup &> /dev/null; then
        if cryptsetup isLuks "$device" 2>/dev/null; then
            encryption_status="LUKS Encrypted"
        else
            # Check partitions for LUKS
            local partitions=$(lsblk -ln -o NAME "$device" 2>/dev/null | grep -v "^$(basename $device)$")
            for partition in $partitions; do
                if cryptsetup isLuks "/dev/$partition" 2>/dev/null; then
                    encryption_status="LUKS Encrypted (Partition)"
                    break
                fi
            done
        fi
    fi
    
    # Check for BitLocker (basic detection)
    if command -v file &> /dev/null; then
        local file_output=$(file -s "$device" 2>/dev/null | grep -i "bitlocker" || true)
        if [ -n "$file_output" ]; then
            encryption_status="BitLocker Encrypted"
        fi
    fi
    
    echo "$encryption_status"
}

# Main device detection function
detect_devices() {
    log_message "Starting device enumeration..."
    
    echo -e "${YELLOW}Scanning for storage devices...${NC}"
    echo
    
    # Initialize JSON structure
    echo '{"devices": [], "detection_timestamp": "'$(date -Iseconds)'", "system_info": {}}' > "$DEVICE_INFO_FILE"
    
    # Get all block devices
    local all_devices=$(lsblk -dn -o NAME | grep -E '^(sd|hd|nvme|vd|xvd)' || true)
    
    local device_count=0
    local external_count=0
    local internal_count=0
    local os_count=0
    
    for device_name in $all_devices; do
        local device="/dev/$device_name"
        
        # Skip if device doesn't exist
        [ ! -b "$device" ] && continue
        
        device_count=$((device_count + 1))
        
        echo -e "${BLUE}Analyzing device: $device${NC}"
        
        # Gather device information
        local device_type=$(get_device_type "$device")
        local device_size=$(get_device_size "$device")
        local is_os=$(is_os_device "$device")
        local smart_info=$(get_smart_info "$device")
        local encryption=$(detect_encryption "$device")
        local is_removable=$(cat "/sys/block/$device_name/removable" 2>/dev/null || echo "0")
        
        # Classify device
        local classification="Internal Drive"
        if [ "$is_removable" = "1" ] || [[ "$device_type" == *"USB"* ]]; then
            classification="External/Removable Drive"
            external_count=$((external_count + 1))
        else
            internal_count=$((internal_count + 1))
        fi
        
        if [ "$is_os" = "true" ]; then
            classification="$classification (Contains OS)"
            os_count=$((os_count + 1))
        fi
        
        # Get filesystem information
        local filesystems=$(lsblk -ln -o NAME,FSTYPE "$device" 2>/dev/null | grep -v "^$device_name " | awk '{print $2}' | grep -v "^$" | sort -u | tr '\n' ',' | sed 's/,$//')
        
        # Display device info
        echo "  Type: $device_type"
        echo "  Size: $device_size"
        echo "  Classification: $classification"
        echo "  Encryption: $encryption"
        echo "  Hardware Info: $smart_info"
        [ -n "$filesystems" ] && echo "  Filesystems: $filesystems"
        
        # Add to JSON
        local device_json=$(cat << EOF
{
  "device": "$device",
  "name": "$device_name",
  "type": "$device_type",
  "size": "$device_size",
  "size_bytes": $(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ' || echo 0),
  "classification": "$classification",
  "is_os_device": $is_os,
  "is_removable": $([ "$is_removable" = "1" ] && echo "true" || echo "false"),
  "encryption": "$encryption",
  "smart_info": "$smart_info",
  "filesystems": "$filesystems",
  "detection_time": "$(date -Iseconds)"
}
EOF
        )
        
        # Append to JSON file
        local temp_file=$(mktemp)
        jq --argjson device "$device_json" '.devices += [$device]' "$DEVICE_INFO_FILE" > "$temp_file" && mv "$temp_file" "$DEVICE_INFO_FILE"
        
        echo
        log_message "Detected device: $device ($device_type, $device_size)"
    done
    
    # Add system information to JSON
    local system_info=$(cat << EOF
{
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "architecture": "$(uname -m)",
  "os": "$(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"' || echo 'Unknown')",
  "total_devices": $device_count,
  "internal_devices": $internal_count,
  "external_devices": $external_count,
  "os_devices": $os_count
}
EOF
    )
    
    local temp_file=$(mktemp)
    jq --argjson sysinfo "$system_info" '.system_info = $sysinfo' "$DEVICE_INFO_FILE" > "$temp_file" && mv "$temp_file" "$DEVICE_INFO_FILE"
    
    # Summary
    echo -e "${GREEN}=================================================="
    echo -e "Detection Summary"
    echo -e "==================================================${NC}"
    echo "Total devices found: $device_count"
    echo "Internal drives: $internal_count"
    echo "External/USB drives: $external_count"
    echo "Drives with OS: $os_count"
    echo
    echo -e "${YELLOW}Device information saved to: $DEVICE_INFO_FILE${NC}"
    echo -e "${YELLOW}Detection log saved to: $LOG_FILE${NC}"
    
    log_message "Device detection completed. Found $device_count devices."
}

# Show detected devices in a formatted table
show_device_table() {
    echo
    echo -e "${BLUE}Detected Storage Devices:${NC}"
    echo "================================================================================================================================"
    printf "%-15s %-15s %-15s %-30s %-20s %-15s\n" "DEVICE" "TYPE" "SIZE" "CLASSIFICATION" "ENCRYPTION" "STATUS"
    echo "================================================================================================================================"
    
    if [ -f "$DEVICE_INFO_FILE" ]; then
        jq -r '.devices[] | [.device, .type, .size, .classification, .encryption, (if .is_os_device then "OS DEVICE" else "SAFE TO WIPE" end)] | @tsv' "$DEVICE_INFO_FILE" | \
        while IFS=$'\t' read -r device type size classification encryption status; do
            local color=$GREEN
            if [[ "$status" == "OS DEVICE" ]]; then
                color=$RED
            elif [[ "$encryption" != "None" ]]; then
                color=$YELLOW
            fi
            printf "${color}%-15s %-15s %-15s %-30s %-20s %-15s${NC}\n" "$device" "$type" "$size" "$classification" "$encryption" "$status"
        done
    fi
    
    echo "================================================================================================================================"
}

# Main function
main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    initialize
    detect_devices
    show_device_table
    
    echo
    echo -e "${GREEN}Device detection completed successfully!${NC}"
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Review the detected devices carefully"
    echo "2. Use secure_wipe.sh to wipe non-OS devices"
    echo "3. Generate certificates with certificate_gen.sh"
    echo
}

# Script entry point
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
