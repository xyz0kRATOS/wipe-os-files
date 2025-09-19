#!/bin/bash

# drive_detection.sh - Secure Drive Detection for Data Wiping Tool
# Compatible with Bookworm Puppy Linux

set -euo pipefail

# Configuration
LOG_FILE="/tmp/drive_detection.log"
OUTPUT_JSON="/tmp/detected_drives.json"

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Initialize JSON structure
init_json() {
    cat > "$OUTPUT_JSON" << 'EOF'
{
  "scan_timestamp": "",
  "detected_drives": [],
  "system_info": {
    "hostname": "",
    "kernel": "",
    "architecture": ""
  }
}
EOF
}

# Get system information
get_system_info() {
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local arch=$(uname -m)

    # Update JSON with system info
    jq --arg hostname "$hostname" \
       --arg kernel "$kernel" \
       --arg arch "$arch" \
       --arg timestamp "$(date -Iseconds)" \
       '.scan_timestamp = $timestamp |
        .system_info.hostname = $hostname |
        .system_info.kernel = $kernel |
        .system_info.architecture = $arch' "$OUTPUT_JSON" > /tmp/temp.json && mv /tmp/temp.json "$OUTPUT_JSON"
}

# Detect storage drives
detect_drives() {
    log_message "Starting drive detection..."

    # Find all block devices (excluding loop, ram, and removable media)
    local drives=$(lsblk -dpno NAME,SIZE,MODEL,SERIAL,TYPE | grep -E "disk$" | grep -v -E "loop|ram" || true)

    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local device=$(echo "$line" | awk '{print $1}')
            local size=$(echo "$line" | awk '{print $2}')
            local model=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^ *//' | awk '{$NF=""; print $0}' | sed 's/ *$//')
            local serial=$(echo "$line" | awk '{print $NF}')

            # Skip if device doesn't exist
            [[ ! -e "$device" ]] && continue

            detect_drive_details "$device" "$size" "$model" "$serial"
        fi
    done <<< "$drives"

    log_message "Drive detection completed"
}

# Get detailed drive information
detect_drive_details() {
    local device="$1"
    local size="$2"
    local model="$3"
    local serial="$4"

    log_message "Analyzing drive: $device"

    # Initialize drive object
    local drive_info='{}'

    # Basic information
    drive_info=$(echo "$drive_info" | jq --arg dev "$device" \
                                        --arg size "$size" \
                                        --arg model "$model" \
                                        --arg serial "$serial" \
                                        '.device = $dev |
                                         .size = $size |
                                         .model = $model |
                                         .serial = $serial')

    # Get drive type (SSD, HDD, NVMe)
    local drive_type="Unknown"
    local interface_type="Unknown"

    if [[ "$device" == *"nvme"* ]]; then
        drive_type="NVMe SSD"
        interface_type="NVMe"
        # Get NVMe specific info
        if command -v nvme &> /dev/null; then
            local nvme_info=$(nvme id-ctrl "$device" 2>/dev/null || echo "")
            if [[ -n "$nvme_info" ]]; then
                local firmware=$(echo "$nvme_info" | grep -i "fr " | awk '{print $3}' || echo "Unknown")
                drive_info=$(echo "$drive_info" | jq --arg fw "$firmware" '.firmware = $fw')
            fi
        fi
    else
        # Check if it's SSD or HDD using rotational attribute
        local rotational=$(cat "/sys/block/$(basename "$device")/queue/rotational" 2>/dev/null || echo "1")
        if [[ "$rotational" == "0" ]]; then
            drive_type="SSD"
            interface_type="SATA"
        else
            drive_type="HDD"
            interface_type="SATA"
        fi

        # Get SATA/ATA specific info
        if command -v hdparm &> /dev/null; then
            local hdparm_info=$(hdparm -I "$device" 2>/dev/null || echo "")
            if [[ -n "$hdparm_info" ]]; then
                local firmware=$(echo "$hdparm_info" | grep -i "firmware revision" | awk -F: '{print $2}' | xargs || echo "Unknown")
                local security_status=$(echo "$hdparm_info" | grep -i "security" | head -1 || echo "Unknown")

                drive_info=$(echo "$drive_info" | jq --arg fw "$firmware" \
                                                    --arg sec "$security_status" \
                                                    '.firmware = $fw |
                                                     .security_status = $sec')

                # Check for HPA/DCO
                local hpa_status="Not Present"
                local dco_status="Not Present"

                if echo "$hdparm_info" | grep -qi "HPA"; then
                    hpa_status="Present"
                fi
                if echo "$hdparm_info" | grep -qi "DCO"; then
                    dco_status="Present"
                fi

                drive_info=$(echo "$drive_info" | jq --arg hpa "$hpa_status" \
                                                    --arg dco "$dco_status" \
                                                    '.hpa_status = $hpa |
                                                     .dco_status = $dco')
            fi
        fi
    fi

    # Add drive type and interface
    drive_info=$(echo "$drive_info" | jq --arg type "$drive_type" \
                                        --arg interface "$interface_type" \
                                        '.drive_type = $type |
                                         .interface = $interface')

    # Check if drive is mounted
    local mount_points=$(lsblk -no MOUNTPOINT "$device" 2>/dev/null | grep -v "^$" || echo "")
    local is_mounted="false"
    if [[ -n "$mount_points" ]]; then
        is_mounted="true"
    fi

    drive_info=$(echo "$drive_info" | jq --arg mounted "$is_mounted" \
                                        --arg mounts "$mount_points" \
                                        '.is_mounted = ($mounted | test("true")) |
                                         .mount_points = $mounts')

    # Get partition information
    local partitions=$(lsblk -no NAME,SIZE,FSTYPE "$device" 2>/dev/null | tail -n +2 || echo "")
    local partition_array="[]"

    while IFS= read -r part_line; do
        if [[ -n "$part_line" ]]; then
            local part_name=$(echo "$part_line" | awk '{print $1}')
            local part_size=$(echo "$part_line" | awk '{print $2}')
            local part_fs=$(echo "$part_line" | awk '{print $3}')

            local part_obj=$(jq -n --arg name "$part_name" \
                                   --arg size "$part_size" \
                                   --arg fs "$part_fs" \
                                   '{name: $name, size: $size, filesystem: $fs}')

            partition_array=$(echo "$partition_array" | jq --argjson obj "$part_obj" '. += [$obj]')
        fi
    done <<< "$partitions"

    drive_info=$(echo "$drive_info" | jq --argjson parts "$partition_array" '.partitions = $parts')

    # Determine wipe capability
    local wipe_capable="true"
    local wipe_methods=[]

    # Add appropriate wipe methods based on drive type
    if [[ "$drive_type" == *"SSD"* ]] || [[ "$drive_type" == *"NVMe"* ]]; then
        wipe_methods=$(echo '[]' | jq '. += ["ATA_SECURE_ERASE", "CRYPTO_ERASE", "NIST_PURGE"]')
    else
        wipe_methods=$(echo '[]' | jq '. += ["ATA_SECURE_ERASE", "DOD_3PASS", "NIST_CLEAR", "NIST_PURGE"]')
    fi

    drive_info=$(echo "$drive_info" | jq --argjson capable true \
                                        --argjson methods "$wipe_methods" \
                                        '.wipe_capable = $capable |
                                         .supported_wipe_methods = $methods')

    # Add timestamp
    drive_info=$(echo "$drive_info" | jq --arg timestamp "$(date -Iseconds)" '.detected_at = $timestamp')

    # Add drive to main JSON
    jq --argjson drive "$drive_info" '.detected_drives += [$drive]' "$OUTPUT_JSON" > /tmp/temp.json && mv /tmp/temp.json "$OUTPUT_JSON"

    log_message "Drive $device analysis completed"
}

# Check for required tools
check_dependencies() {
    local missing_tools=()

    local required_tools=("lsblk" "jq" "hdparm" "nvme" "sgdisk")

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "WARNING: Missing tools: ${missing_tools[*]}"
        log_message "Some drive detection features may be limited"
    fi
}

# Main execution
main() {
    log_message "Starting secure drive detection system"

    # Check dependencies
    check_dependencies

    # Initialize JSON output
    init_json

    # Get system information
    get_system_info

    # Detect all drives
    detect_drives

    # Output results
    log_message "Drive detection completed. Results saved to: $OUTPUT_JSON"

    # Display summary
    local drive_count=$(jq '.detected_drives | length' "$OUTPUT_JSON")
    log_message "Total drives detected: $drive_count"

    # Show detected drives summary
    echo ""
    echo "=== DETECTED DRIVES SUMMARY ==="
    jq -r '.detected_drives[] | "Device: \(.device) | Model: \(.model) | Type: \(.drive_type) | Size: \(.size)"' "$OUTPUT_JSON"
    echo ""

    return 0
}

# Execute if run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

