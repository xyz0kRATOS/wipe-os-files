#!/usr/bin/env bash
# wipe_device.sh
# Usage: sudo bash wipe_device.sh [--dry-run] [--n-pass N] /dev/sdx [/dev/nvme0n1 ...]
#
# Notes: Very destructive. Must be run as root.
# Methods: choose by device properties (rotational, nvme, ata)
#
set -euo pipefail

DRY_RUN=0
NPASS=1
REPORT_DIR=""
FORCE_NO_PROMPT=0

# parse args
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --n-pass) NPASS="$2"; shift 2;;
    --report-dir) REPORT_DIR="$2"; shift 2;;
    --yes|--force) FORCE_NO_PROMPT=1; shift;;
    --help) sed -n '1,200p' "$0"; exit 0;;
    *) args+=("$1"); shift;;
  esac
done

if [[ ${#args[@]} -lt 1 ]]; then
  echo "Usage: sudo bash wipe_device.sh [--dry-run] [--n-pass N] [--report-dir DIR] [--yes] /dev/sdx ..."
  exit 2
fi

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root"
  exit 2
fi

# set report dir default: detect mounted removable (try /run/media/$USER, /media, /mnt/usb)
if [[ -z "$REPORT_DIR" ]]; then
  if compgen -G "/run/media/*/*" >/dev/null 2>&1; then
    REPORT_DIR=$(ls -d /run/media/*/* | head -n1)/wipe_reports || true
  elif compgen -G "/media/*" >/dev/null 2>&1; then
    REPORT_DIR=/media/$(ls /media | head -n1)/wipe_reports || true
  else
    REPORT_DIR="/var/log/wipe_reports"
  fi
fi

mkdir -p "$REPORT_DIR"
LOGFILE="$REPORT_DIR/wipe_$(date --iso-8601=seconds).log"
touch "$LOGFILE"
chmod 600 "$LOGFILE"

echo "Wipe run started at $(date --iso-8601=seconds)" | tee -a "$LOGFILE"

# check required tools
REQ=(lsblk hdparm nvme blkdiscard shred dd sync)
for r in "${REQ[@]}"; do
  if ! command -v "$r" >/dev/null 2>&1; then
    echo "WARN: $r not available. Some operations may not be possible." | tee -a "$LOGFILE"
  fi
done

sanitization_log() {
  echo "$(date --iso-8601=seconds) - $*" | tee -a "$LOGFILE"
}

confirm() {
  local prompt="$1"
  if [[ $FORCE_NO_PROMPT -eq 1 ]]; then
    return 0
  fi
  read -rp "$prompt (yes/no): " resp
  if [[ "$resp" != "yes" ]]; then
    echo "Aborted by user." | tee -a "$LOGFILE"
    return 1
  fi
  return 0
}

# helpers
is_nvme() {
  [[ "$1" =~ ^/dev/nvme ]]
}
is_ata() {
  # basic heuristic: /dev/sd*
  [[ "$1" =~ ^/dev/sd ]]
}
is_rotational() {
  local devname
  devname=$(basename "$1")
  if [[ -e "/sys/block/$devname/queue/rotational" ]]; then
    cat /sys/block/$devname/queue/rotational
    return 0
  fi
  echo "unknown"
}

do_overwrite_passes() {
  local dev="$1"
  local passes="$2"
  if [[ $DRY_RUN -eq 1 ]]; then
    sanitization_log "DRY RUN: would overwrite $dev with $passes pass(es) of /dev/urandom"
    return 0
  fi

  # Use shred if present (it will write multiple passes and optionally remove)
  if command -v shred >/dev/null 2>&1; then
    sanitization_log "Running shred -n ${passes} -v $dev"
    shred -n "$passes" -v "$dev" | tee -a "$LOGFILE"
    sync
  else
    # fallback: dd from /dev/urandom for each pass
    for ((i=1;i<=passes;i++)); do
      sanitization_log "dd pass $i -> $dev"
      # use bs=4M for speed; adjust if needed
      dd if=/dev/urandom of="$dev" bs=4M status=progress conv=fsync 2>&1 | tee -a "$LOGFILE" || true
      sync
    done
  fi
}

do_hdparm_secure_erase() {
  local dev="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    sanitization_log "DRY RUN: would attempt hdparm secure erase on $dev"
    return 0
  fi
  if ! command -v hdparm >/dev/null 2>&1; then
    sanitization_log "hdparm not available"
    return 1
  fi

  sanitization_log "Attempting hdparm security status on $dev"
  hdparm --user-master u --security-set-pass NULL "$dev" 2>&1 | tee -a "$LOGFILE" || true
  hdparm --user-master u --security-erase NULL "$dev" 2>&1 | tee -a "$LOGFILE" || true
}

do_nvme_secure_erase() {
  local dev="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    sanitization_log "DRY RUN: would attempt nvme format sanitize on $dev"
    return 0
  fi
  if ! command -v nvme >/dev/null 2>&1; then
    sanitization_log "nvme-cli not installed"
    return 1
  fi
  # use --ses=1 (cryptographic erase) if supported; fallback to sanitize
  sanitization_log "Running nvme format --ses=1 $dev"
  nvme format --ses=1 "$dev" 2>&1 | tee -a "$LOGFILE" || true
}

do_blkdiscard() {
  local dev="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    sanitization_log "DRY RUN: would run blkdiscard on $dev"
    return 0
  fi
  if ! command -v blkdiscard >/dev/null 2>&1; then
    sanitization_log "blkdiscard not available"
    return 1
  fi
  sanitization_log "Running blkdiscard $dev"
  blkdiscard -v "$dev" 2>&1 | tee -a "$LOGFILE" || true
}

# main loop over devices
for dev in "${args[@]}"; do
  if [[ ! -b "$dev" ]]; then
    echo "Device $dev not found or not a block device. Skipping." | tee -a "$LOGFILE"
    continue
  fi

  devname=$(basename "$dev")
  rot=$(is_rotational "$dev")
  sanitization_log "Processing device $dev (rotational=$rot)"

  # show top-level info to user
  lsblk -o NAME,SIZE,TYPE,MOUNTPOINT "$dev" | tee -a "$LOGFILE"
  blkid "$dev" 2>/dev/null | tee -a "$LOGFILE" || true

  # safety: do not allow wiping of running root or mounted devices
  if mount | grep -q "$dev"; then
    echo "ERROR: $dev or its partitions appear mounted. Unmount first." | tee -a "$LOGFILE"
    continue
  fi
  if [[ "$(findmnt -n -o SOURCE / 2>/dev/null || true)" == "$dev"* ]]; then
    echo "ERROR: $dev is the running OS device. Refusing to wipe the live system." | tee -a "$LOGFILE"
    continue
  fi

  echo
  echo "SELECTED: $dev"
  echo "Detected rotational: $rot"
  echo

  # confirmation
  if ! confirm "Permanently wipe $dev? Type 'yes' to proceed"; then
    continue
  fi

  # choose method priority: NVMe secure -> ATA secure -> blkdiscard -> overwrite
  if is_nvme "$dev"; then
    sanitization_log "Device is NVMe"
    # try nvme secure erase
    do_nvme_secure_erase "$dev"
    # as fallback try blkdiscard
    do_blkdiscard "$dev"
    # if NPASS>0 fallback to overwrite (note: may be ineffective on some SSDs)
    if [[ "$NPASS" -gt 0 ]]; then
      do_overwrite_passes "$dev" "$NPASS"
    fi
    sanitization_log "Finished NVMe sanitization steps for $dev"
  elif is_ata "$dev"; then
    sanitization_log "Device looks like ATA (/dev/sd*)"
    # try hdparm secure erase
    do_hdparm_secure_erase "$dev" || true
    # try blkdiscard for SSDs
    if [[ "$rot" == "0" ]]; then
      do_blkdiscard "$dev" || true
    fi
    # fallback overwrite
    do_overwrite_passes "$dev" "$NPASS"
    sanitization_log "Finished ATA sanitization steps for $dev"
  else
    sanitization_log "Unknown device type; using overwrite method."
    do_overwrite_passes "$dev" "$NPASS"
    sanitization_log "Finished overwrite for $dev"
  fi

  # attempt to wipe partition table
  if [[ $DRY_RUN -eq 1 ]]; then
    sanitization_log "DRY RUN: would wipe partition table on $dev (sgdisk --zap-all)"
  else
    if command -v sgdisk >/dev/null 2>&1; then
      sanitization_log "Wiping partition table (sgdisk --zap-all)"
      sgdisk --zap-all "$dev" 2>&1 | tee -a "$LOGFILE" || true
    else
      sanitization_log "sgdisk unavailable; zeroing first 2MB of device to remove partition table"
      dd if=/dev/zero of="$dev" bs=1M count=2 status=none || true
      sync
    fi
  fi

  sanitization_log "Syncing and finalizing for $dev"
  sync

  # record a short summary entry
  echo "{\"device\":\"$dev\",\"time\":\"$(date --iso-8601=seconds)\",\"method\":\"auto\",\"n_pass\":\"$NPASS\"}" >> "$REPORT_DIR/summary.log"

done

sanitization_log "Wipe run completed."
echo "Logs saved to $LOGFILE"


