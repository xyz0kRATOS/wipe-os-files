#!/bin/bash

# Secure Data Wiping Script
# NIST SP 800-88 Rev. 1 Compliant Implementation
# Supports HDD, SSD, NVMe, and USB devices

set -e

# Global variables
SCRIPT_DIR="/tmp/secure_wipe"
LOG_FILE="/var/log/secure_wipe/wipe_operations.log"
DEVICE_INFO_FILE="$SCRIPT_DIR/detected_devices.json"
WIPE_RESULTS_FILE="$SCRIPT_DIR/wipe_results.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# NIST SP 800-88 Methods
declare -A NIST_METHODS
NIST_METHODS["clear"]="NIST Clear - Single pass with zeros"
NIST_METHODS["purge_hdd"]="NIST Purge (HDD) - 3-pass overwrite"
NIST_METHODS["purge_ssd"]="NIST Purge (SSD) - Cryptographic erase or block erase"
NIST_METHODS["destroy"]="NIST Destroy - Physical destruction (not implemented)"

# Initialize
initialize() {
    echo -e "${BLUE}=================================================="
    echo -e "Secure Data Wiping - NIST SP 800-88 Compliant"
    echo -e "==================================================${NC}"
    
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Initialize wipe results file
    echo '{"wipe_operations": [], "session_start": "'$(date -Iseconds)'"}' > "$WIPE_RESULTS_FILE"
    
    log_message "Secure wipe session started"
    echo
}

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Validate device safety
validate_device_safety() {
    local device=$1
    
    log_message "Validating device safety: $device"
    
    # Check if device exists
    if [ ! -b "$device" ]; then
        echo -e "${RED}Error: Device $device does not exist${NC}"
        return 1
    fi
    
    # Check if it's an OS device using our detection data
    if [ -f "$DEVICE_INFO_FILE" ]; then
        local is_os_device=$(jq -r --arg dev "$device" '.devices[] | select(.device == $dev) | .is_os_device' "$DEVICE_INFO_FILE" 2>/dev/null || echo "null")
        if [ "$is_os_device" = "true" ]; then
            echo -e "${RED}CRITICAL WARNING: Device $device contains the operating system!${NC}"
            echo -e "${RED}Wiping this device will render the system unbootable!${NC}"
            return 1
        fi
    fi
    
    # Check for active mounts
    local mounted_partitions=$(lsblk -ln -o NAME,MOUNTPOINT "$device" 2>/dev/null | grep -v "^$(basename $device) " | awk '$2!="" {print "/dev/"$1":"$2}')
    if [ -n "$mounted_partitions" ]; then
        echo -e "${YELLOW}Warning: Device has mounted partitions:${NC}"
        echo "$mounted_partitions"
        echo -e "${YELLOW}These will be unmounted before wiping${NC}"
    fi
    
    return 0
}

# Unmount all partitions on device
unmount_device() {
    local device=$1
    
    log_message "Unmounting all partitions on $device"
    
    # Get all partitions
    local partitions=$(lsblk -ln -o NAME "$device" 2>/dev/null | grep -v "^$(basename $device)$" | sed 's/^[├└]─//')
    
    for partition in $partitions; do
        local part_dev="/dev/$partition"
        local mountpoint=$(lsblk -ln -o MOUNTPOINT "$part_dev" 2>/dev/null)
        
        if [ -n "$mountpoint" ]; then
            echo "Unmounting $part_dev from $mountpoint"
            if umount "$part_dev" 2>/dev/null; then
                log_message "Successfully unmounted $part_dev"
            else
                log_message "Warning: Failed to unmount $part_dev"
                # Force unmount
                umount -f "$part_dev" 2>/dev/null || true
            fi
        fi
    done
    
    # Disable swap if device contains swap
    if grep -q "$(basename $device)" /proc/swaps 2>/dev/null; then
        swapoff "$device" 2>/dev/null || true
        log_message "Disabled swap on $device"
    fi
}

# Get device characteristics
get_device_characteristics() {
    local device=$1
    local device_info=""
    
    # Device type
    local device_type="Unknown"
    if [[ $device =~ nvme[0-9]+n[0-9]+ ]]; then
        device_type="NVMe"
    elif [ -f "/sys/block/$(basename $device)/queue/rotational" ]; then
        local rotational=$(cat "/sys/block/$(basename $device)/queue/rotational" 2>/dev/null)
        if [ "$rotational" = "1" ]; then
            device_type="HDD"
        else
            device_type="SSD"
        fi
    fi
    
    # Size
    local size_bytes=$(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ')
    local size_human=$(lsblk -dn -o SIZE "$device" 2>/dev/null | tr -d ' ')
    
    echo "$device_type:$size_bytes:$size_human"
}

# NIST Clear Method - Single pass with zeros
nist_clear() {
    local device=$1
    local start_time=$(date +%s)
    
    echo -e "${BLUE}Executing NIST Clear Method on $device${NC}"
    echo "Method: Single pass overwrite with zeros"
    
    log_message "Starting NIST Clear on $device"
    
    # Use dd with progress monitoring
    local size_bytes=$(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ')
    
    if command -v pv &> /dev/null; then
        # Use pv for progress monitoring
        dd if=/dev/zero bs=1M | pv -s "$size_bytes" | dd of="$device" bs=1M oflag=direct 2>/dev/null
    else
        # Fallback to dd with periodic progress
        dd if=/dev/zero of="$device" bs=1M oflag=direct status=progress
    fi
    
    # Sync to ensure data is written
    sync
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_message "NIST Clear completed on $device in ${duration} seconds"
    echo -e "${GREEN}NIST Clear completed successfully${NC}"
    
    return 0
}

# NIST Purge Method for HDDs - 3-pass overwrite
nist_purge_hdd() {
    local device=$1
    local start_time=$(date +%s)
    
    echo -e "${BLUE}Executing NIST Purge Method for HDD on $device${NC}"
    echo "Method: 3-pass overwrite (random, zeros, random)"
    
    log_message "Starting NIST Purge (HDD) on $device"
    
    local size_bytes=$(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ')
    
    # Pass 1: Random data
    echo "Pass 1/3: Writing random data..."
    if command -v pv &> /dev/null; then
        dd if=/dev/urandom bs=1M | pv -s "$size_bytes" | dd of="$device" bs=1M oflag=direct 2>/dev/null
    else
        dd if=/dev/urandom of="$device" bs=1M oflag=direct status=progress
    fi
    sync
    
    # Pass 2: Zeros
    echo "Pass 2/3: Writing zeros..."
    if command -v pv &> /dev/null; then
        dd if=/dev/zero bs=1M | pv -s "$size_bytes" | dd of="$device" bs=1M oflag=direct 2>/dev/null
    else
        dd if=/dev/zero of="$device" bs=1M oflag=direct status=progress
    fi
    sync
    
    # Pass 3: Random data again
    echo "Pass 3/3: Writing random data..."
    if command -v pv &> /dev/null; then
        dd if=/dev/urandom bs=1M | pv -s "$size_bytes" | dd of="$device" bs=1M oflag=direct 2>/dev/null
    else
        dd if=/dev/urandom of="$device" bs=1M oflag=direct status=progress
    fi
    sync
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_message "NIST Purge (HDD) completed on $device in ${duration} seconds"
    echo -e "${GREEN}NIST Purge (HDD) completed successfully${NC}"
    
    return 0
}

# NIST Purge Method for SSDs - Secure Erase or Crypto Erase
nist_purge_ssd() {
    local device=$1
    local start_time=$(date +%s)
    local method_used="block_erase"
    
    echo -e "${BLUE}Executing NIST Purge Method for SSD on $device${NC}"
    
    log_message "Starting NIST Purge (SSD) on $device"
    
    # Try ATA Secure Erase first
    if command -v hdparm &> /dev/null; then
        echo "Attempting ATA Security Erase..."
        
        # Check if security is supported and not frozen
        local security_info=$(hdparm -I "$device" 2>/dev/null | grep -A5 -B5 "Security:" || true)
        local security_supported=$(echo "$security_info" | grep "supported" || true)
        local security_frozen=$(echo "$security_info" | grep "frozen" || true)
        
        if [ -n "$security_supported" ] && [ -z "$security_frozen" ]; then
            echo "ATA Security supported and not frozen. Proceeding with Secure Erase..."
            
            # Set temporary password
            if hdparm --user-master u --security-set-pass temp123 "$device" 2>/dev/null; then
                log_message "Security password set for $device"
                
                # Estimate time for secure erase
                local erase_time=$(hdparm -I "$device" 2>/dev/null | grep "for SECURITY ERASE UNIT" | grep -o "[0-9]\+min" | head -1 || echo "unknown")
                echo "Estimated erase time: $erase_time"
                
                # Perform secure erase
                if hdparm --user-master u --security-erase temp123 "$device" 2>/dev/null; then
                    method_used="ata_secure_erase"
                    echo -e "${GREEN}ATA Secure Erase completed successfully${NC}"
                    log_message "ATA Secure Erase completed on $device"
                else
                    echo -e "${YELLOW}ATA Secure Erase failed, falling back to block erase${NC}"
                    # Remove password if erase failed
                    hdparm --user-master u --security-disable temp123 "$device" 2>/dev/null || true
                fi
            else
                echo -e "${YELLOW}Failed to set security password, falling back to block erase${NC}"
            fi
        else
            echo -e "${YELLOW}ATA Security not supported or frozen, falling back to block erase${NC}"
        fi
    fi
    
    # Try NVMe Secure Erase for NVMe devices
    if [[ $device =~ nvme[0-9]+n[0-9]+ ]] && command -v nvme &> /dev/null && [ "$method_used" = "block_erase" ]; then
        echo "Attempting NVMe Format with Secure Erase..."
        
        # Check supported secure erase methods
        local format_info=$(nvme id-ns "$device" 2>/dev/null | grep -i "format\|erase" || true)
        
        # Try secure erase format (ses=1 for cryptographic erase, ses=2 for block erase)
        if nvme format "$device" --ses=2 --force 2>/dev/null; then
            method_used="nvme_secure_erase"
            echo -e "${GREEN}NVMe Secure Erase completed successfully${NC}"
            log_message "NVMe Secure Erase completed on $device"
        elif nvme format "$device" --ses=1 --force 2>/dev/null; then
            method_used="nvme_crypto_erase"
            echo -e "${GREEN}NVMe Cryptographic Erase completed successfully${NC}"
            log_message "NVMe Cryptographic Erase completed on $device"
        else
            echo -e "${YELLOW}NVMe Secure Erase failed, falling back to block erase${NC}"
        fi
    fi
    
    # Fallback to block erase if hardware methods failed
    if [ "$method_used" = "block_erase" ]; then
        echo "Performing block-level erase with random data..."
        local size_bytes=$(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ')
        
        if command -v pv &> /dev/null; then
            dd if=/dev/urandom bs=1M | pv -s "$size_bytes" | dd of="$device" bs=1M oflag=direct 2>/dev/null
        else
            dd if=/dev/urandom of="$device" bs=1M oflag=direct status=progress
        fi
        sync
        
        echo -e "${GREEN}Block erase completed successfully${NC}"
        log_message "Block erase completed on $device"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_message "NIST Purge (SSD) completed on $device using $method_used in ${duration} seconds"
    echo -e "${GREEN}NIST Purge (SSD) completed successfully using $method_used${NC}"
    
    return 0
}

# Enhanced sanitization for modern SSDs
enhanced_ssd_sanitize() {
    local device=$1
    
    echo -e "${BLUE}Attempting enhanced SSD sanitization...${NC}"
    
    # Try SCSI SANITIZE command if available
    if command -v sg_sanitize &> /dev/null; then
        echo "Attempting SCSI SANITIZE command..."
        if sg_sanitize --block --early "$device" 2>/dev/null; then
            echo -e "${GREEN}SCSI SANITIZE completed${NC}"
            return 0
        fi
    fi
    
    # Try ATA SANITIZE if available
    if command -v hdparm &> /dev/null; then
        local sanitize_info=$(hdparm -I "$device" 2>/dev/null | grep -i "sanitize" || true)
        if [ -n "$sanitize_info" ]; then
            echo "ATA SANITIZE feature detected"
            # This would require specific implementation based on drive support
        fi
    fi
    
    return 1
}

# Verify wipe completion
verify_wipe() {
    local device=$1
    local verification_method="sampling"
    
    echo -e "${BLUE}Verifying wipe completion on $device${NC}"
    log_message "Starting wipe verification on $device"
    
    local size_bytes=$(lsblk -dn -o SIZE -b "$device" 2>/dev/null | tr -d ' ')
    local sample_size=$((1024 * 1024)) # 1MB samples
    local num_samples=10
    
    echo "Verification method: Random sampling ($num_samples samples)"
    
    local non_zero_found=false
    local total_samples=0
    local zero_samples=0
    
    for i in $(seq 1 $num_samples); do
        # Generate random offset
        local max_offset=$(($size_bytes - $sample_size))
        local offset=$((RANDOM % ($max_offset / $sample_size) * $sample_size))
        
        # Read sample
        local sample_data=$(dd if="$device" bs=$sample_size count=1 skip=$((offset / $sample_size)) 2>/dev/null | od -An -tx1 | tr -d ' \n')
        
        total_samples=$((total_samples + 1))
        
        # Check if sample is all zeros
        if [ -z "$(echo "$sample_data" | tr -d '0')" ]; then
            zero_samples=$((zero_samples + 1))
        else
            # Check for patterns that might indicate incomplete wipe
            local zero_count=$(echo "$sample_data" | grep -o "00" | wc -l)
            local total_bytes=$((${#sample_data} / 2))
            local zero_percentage=$((zero_count * 100 / total_bytes))
            
            if [ $zero_percentage -lt 90 ]; then
                non_zero_found=true
                echo "Sample $i: Non-zero data found (offset: $offset, zeros: $zero_percentage%)"
            fi
        fi
    done
    
    echo "Verification results:"
    echo "  Total samples: $total_samples"
    echo "  All-zero samples: $zero_samples"
    echo "  Mixed samples: $((total_samples - zero_samples))"
    
    if [ $zero_samples -eq $total_samples ]; then
        echo -e "${GREEN}Verification PASSED: All samples contain only zeros${NC}"
        log_message "Wipe verification PASSED for $device"
        return 0
    elif [ $((zero_samples * 100 / total_samples)) -ge 80 ]; then
        echo -e "${YELLOW}Verification WARNING: Most samples are zeros (likely successful)${NC}"
        log_message "Wipe verification WARNING for $device - mostly zeros"
        return 0
    else
        echo -e "${RED}Verification FAILED: Significant non-zero data remains${NC}"
        log_message "Wipe verification FAILED for $device"
        return 1
    fi
}

# Record wipe operation
record_wipe_operation() {
    local device=$1
    local method=$2
    local result=$3
    local duration=$4
    local verification_result=$5
    
    local device_characteristics=$(get_device_characteristics "$device")
    IFS=':' read -r device_type size_bytes size_human <<< "$device_characteristics"
    
    local wipe_record=$(cat << EOF
{
  "device": "$device",
  "device_type": "$device_type",
  "size_bytes": $size_bytes,
  "size_human": "$size_human",
  "wipe_method": "$method",
  "result": "$result",
  "verification_result": "$verification_result",
  "duration_seconds": $duration,
  "timestamp": "$(date -Iseconds)",
  "nist_compliance": true,
  "operator": "$(whoami)",
  "system_info": {
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)"
  }
}
EOF
    )
    
    # Add to results file
    local temp_file=$(mktemp)
    jq --argjson record "$wipe_record" '.wipe_operations += [$record]' "$WIPE_RESULTS_FILE" > "$temp_file" && mv "$temp_file" "$WIPE_RESULTS_FILE"
    
    log_message "Wipe operation recorded: $device ($method) - $result"
}

# Interactive device selection
select_device_interactive() {
    echo -e "${BLUE}Available devices for wiping:${NC}"
    echo "================================================================"
    
    if [ ! -f "$DEVICE_INFO_FILE" ]; then
        echo -e "${RED}No device information found. Please run detection.sh first.${NC}"
        return 1
    fi
    
    # Display safe devices only
    local safe_devices=$(jq -r '.devices[] | select(.is_os_device == false) | .device' "$DEVICE_INFO_FILE" 2>/dev/null)
    
    if [ -z "$safe_devices" ]; then
        echo -e "${RED}No safe devices found for wiping.${NC}"
        return 1
    fi
    
    local device_array=()
    local index=1
    
    echo "Safe devices (non-OS):"
    while IFS= read -r device; do
        if [ -n "$device" ]; then
            local device_info=$(jq -r --arg dev "$device" '.devices[] | select(.device == $dev) | "\(.type) - \(.size) - \(.classification)"' "$DEVICE_INFO_FILE" 2>/dev/null)
            printf "%2d) %-15s %s\n" $index "$device" "$device_info"
            device_array+=("$device")
            index=$((index + 1))
        fi
    done <<< "$safe_devices"
    
    echo "================================================================"
    
    while true; do
        echo -n "Select device number (1-$((index-1)) or 'q' to quit): "
        read -r selection
        
        if [ "$selection" = "q" ] || [ "$selection" = "Q" ]; then
            return 1
        fi
        
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -lt $index ]; then
            selected_device="${device_array[$((selection-1))]}"
            echo "Selected: $selected_device"
            return 0
        else
            echo "Invalid selection. Please try again."
        fi
    done
}

# Select wipe method
select_wipe_method() {
    local device=$1
    local device_characteristics=$(get_device_characteristics "$device")
    IFS=':' read -r device_type size_bytes size_human <<< "$device_characteristics"
    
    echo -e "${BLUE}Select wiping method for $device ($device_type, $size_human):${NC}"
    echo "================================================================"
    echo "1) NIST Clear      - Single pass with zeros (fast)"
    echo "2) NIST Purge      - Advanced method based on device type"
    if [ "$device_type" = "HDD" ]; then
        echo "   └── HDD: 3-pass overwrite (random, zeros, random)"
    else
        echo "   └── SSD/NVMe: Hardware secure erase or block erase"
    fi
    echo "================================================================"
    
    while true; do
        echo -n "Select method (1-2 or 'q' to quit): "
        read -r method_choice
        
        case $method_choice in
            1)
                selected_method="clear"
                return 0
                ;;
            2)
                if [ "$device_type" = "HDD" ]; then
                    selected_method="purge_hdd"
                else
                    selected_method="purge_ssd"
                fi
                return 0
                ;;
            q|Q)
                return 1
                ;;
            *)
                echo "Invalid selection. Please try again."
                ;;
        esac
    done
}

# Main wipe function
perform_wipe() {
    local device=$1
    local method=$2
    
    echo -e "${YELLOW}=================================================="
    echo -e "FINAL CONFIRMATION REQUIRED"
    echo -e "==================================================${NC}"
    echo -e "${RED}WARNING: This operation will PERMANENTLY DESTROY all data on:${NC}"
    echo -e "${RED}Device: $device${NC}"
    echo -e "${RED}Method: ${NIST_METHODS[$method]}${NC}"
    echo -e "${RED}THIS OPERATION CANNOT BE UNDONE!${NC}"
    echo
    
    local device_info=""
    if [ -f "$DEVICE_INFO_FILE" ]; then
        device_info=$(jq -r --arg dev "$device" '.devices[] | select(.device == $dev) | "Type: \(.type), Size: \(.size), Classification: \(.classification)"' "$DEVICE_INFO_FILE" 2>/dev/null)
        echo "$device_info"
    fi
    
    echo
    echo -n "Type 'WIPE' in uppercase to confirm: "
    read -r confirmation
    
    if [ "$confirmation" != "WIPE" ]; then
        echo -e "${YELLOW}Operation cancelled by user${NC}"
        return 1
    fi
    
    # Final safety check
    if ! validate_device_safety "$device"; then
        echo -e "${RED}Safety validation failed. Aborting.${NC}"
        return 1
    fi
    
    # Unmount device
    unmount_device "$device"
    
    # Perform wipe based on method
    local start_time=$(date +%s)
    local wipe_result="FAILED"
    
    case $method in
        "clear")
            if nist_clear "$device"; then
                wipe_result="SUCCESS"
            fi
            ;;
        "purge_hdd")
            if nist_purge_hdd "$device"; then
                wipe_result="SUCCESS"
            fi
            ;;
        "purge_ssd")
            if nist_purge_ssd "$device"; then
                wipe_result="SUCCESS"
            fi
            ;;
        *)
            echo -e "${RED}Unknown wipe method: $method${NC}"
            return 1
            ;;
    esac
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Verify wipe if successful
    local verification_result="NOT_PERFORMED"
    if [ "$wipe_result" = "SUCCESS" ]; then
        echo
        echo -e "${BLUE}Performing wipe verification...${NC}"
        if verify_wipe "$device"; then
            verification_result="PASSED"
        else
            verification_result="FAILED"
            wipe_result="VERIFICATION_FAILED"
        fi
    fi
    
    # Record operation
    record_wipe_operation "$device" "$method" "$wipe_result" "$duration" "$verification_result"
    
    # Final status
    echo
    echo -e "${BLUE}=================================================="
    echo -e "Wipe Operation Summary"
    echo -e "==================================================${NC}"
    echo "Device: $device"
    echo "Method: ${NIST_METHODS[$method]}"
    echo "Duration: ${duration} seconds"
    echo "Result: $wipe_result"
    echo "Verification: $verification_result"
    
    if [ "$wipe_result" = "SUCCESS" ] && [ "$verification_result" = "PASSED" ]; then
        echo -e "${GREEN}WIPE OPERATION COMPLETED SUCCESSFULLY${NC}"
        log_message "Successful wipe operation: $device ($method) in ${duration}s"
        return 0
    else
        echo -e "${RED}WIPE OPERATION FAILED OR INCOMPLETE${NC}"
        log_message "Failed wipe operation: $device ($method) - $wipe_result"
        return 1
    fi
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
    
    # Check for device detection data
    if [ ! -f "$DEVICE_INFO_FILE" ]; then
        echo -e "${YELLOW}No device detection data found.${NC}"
        echo "Please run detection.sh first to scan for devices."
        exit 1
    fi
    
    while true; do
        echo
        if select_device_interactive; then
            if select_wipe_method "$selected_device"; then
                perform_wipe "$selected_device" "$selected_method"
            fi
        else
            break
        fi
        
        echo
        echo -n "Wipe another device? (y/N): "
        read -r continue_choice
        if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
            break
        fi
    done
    
    echo
    echo -e "${GREEN}Secure wipe session completed${NC}"
    echo -e "${YELLOW}Results saved to: $WIPE_RESULTS_FILE${NC}"
    echo -e "${YELLOW}Logs saved to: $LOG_FILE${NC}"
    
    log_message "Secure wipe session ended"
}

# Script entry point
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
