#!/usr/bin/env bash
# detect_devices.sh
# Detect block devices and classify them:
#   - os_drive: device containing current running root filesystem
#   - internal_no_os: internal disks without the running OS
#   - external_removable: USB/removable devices
#
# Output: JSON to /var/log/wipe_detect.json and to stdout
#
# Run as root.

set -euo pipefail

OUT="/var/log/wipe_detect.json"
TIMESTAMP="$(date --iso-8601=seconds)"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root."
  exit 2
fi

# required commands
for cmd in lsblk awk blkid readlink realpath jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command '$cmd' not found. Install it (e.g. apt-get install util-linux jq blkid)."
    exit 2
  fi
done

# find running root device
ROOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null || true)
# normalize to whole-disk device (e.g. /dev/sda1 -> /dev/sda)
norm_dev() {
  local d=$1
  # resolve symlink
  if [[ -L "$d" ]]; then d=$(readlink -f "$d"); fi
  # remove partition number if present
  echo "$d" | sed -E 's/([a-z]+)([0-9]+)$/\1/'
}

ROOT_DISK=""
if [[ -n "$ROOT_DEV" ]]; then
  ROOT_DISK=$(norm_dev "$ROOT_DEV")
fi

# iterate block devices
devices=()
while read -r name rm rota model vendor tran type size mountpoint; do
  DEV="/dev/$name"
  # skip loop devices and RAM
  if [[ "$type" == "loop" || "$type" == "rom" ]]; then continue; fi

  # detect removable via sysfs (1=removable)
  REMOVABLE="0"
  if [[ -e "/sys/block/$name/removable" ]]; then
    REMOVABLE=$(cat /sys/block/$name/removable)
  fi

  # detect transport: nvme, usb, sata, scsi
  TRANSPORT="$tran"
  # detect rotational: 1=HDD, 0=SSD (if available)
  ROTA_VAL="unknown"
  if [[ -e "/sys/block/$name/queue/rotational" ]]; then
    ROTA_VAL=$(cat /sys/block/$name/queue/rotational)
  fi

  # vendor/model may be empty; use blkid to get UUIDs/labels
  UUIDS=$(blkid -s UUID -o value "$DEV" 2>/dev/null || true)
  PARTS=$(lsblk -n -o NAME,MOUNTPOINT -r "/dev/$name" | awk '$2!=""{print $0}' || true)
  CLASS="internal_no_os"
  if [[ -n "$ROOT_DISK" && "/dev/$name" == "$ROOT_DISK" ]]; then
    CLASS="os_drive"
  elif [[ "$REMOVABLE" -eq 1 || "$TRANSPORT" == "usb" || "$TRANSPORT" == "mmc" ]]; then
    CLASS="external_removable"
  fi

  devices+=("{
    \"name\": \"$name\",
    \"dev\": \"$DEV\",
    \"size\": \"$size\",
    \"type\": \"$type\",
    \"transport\": \"$TRANSPORT\",
    \"removable\": $REMOVABLE,
    \"rotational\": \"$ROTA_VAL\",
    \"model\": \"$(echo "$model" | sed 's/"/\\"/g')\",
    \"vendor\": \"$(echo "$vendor" | sed 's/"/\\"/g')\",
    \"mounts\": \"$(echo "$PARTS" | sed 's/\"/\\"/g')\",
    \"uuid\": \"$(echo "$UUIDS" | sed 's/\"/\\"/g')\",
    \"class\": \"$CLASS\"
  }")
done < <(lsblk -d -o NAME,RM,ROTA,MODEL,VENDOR,TRAN,TYPE,SIZE,MOUNTPOINT -P | sed 's/=/=/g' | while read -r line; do
  # convert KEY="value" to space separated fields for awk
  # we'll use lsblk -P which prints plumb output
  eval "declare -A a=(); $(
    for kv in $line; do
      k=${kv%%=*}
      v=${kv#*=}
      v=${v#\"}; v=${v%\"}
      printf 'a[%q]=%q; ' "$k" "$v"
    done
    printf 'echo "${a[NAME]} ${a[RM]} ${a[ROTA]} ${a[MODEL]} ${a[VENDOR]} ${a[TRAN]} ${a[TYPE]} ${a[SIZE]} ${a[MOUNTPOINT]}"'
  )"
done)

# assemble JSON
json="{\
\"generated_at\":\"$TIMESTAMP\",\
\"root_device\":\"$ROOT_DEV\",\
\"root_disk\":\"$ROOT_DISK\",\
\"devices\":["
first=1
for d in "${devices[@]}"; do
  if [[ $first -eq 1 ]]; then first=0; else json+=",${d}"; fi
  json+="${d}"
done
json+="]}"

# pretty print if jq available
echo "$json" | jq '.' > "$OUT"
chmod 644 "$OUT"
echo "Detection written to $OUT"
cat "$OUT"


