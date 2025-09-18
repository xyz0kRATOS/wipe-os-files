#!/usr/bin/env bash
# generate_certificate.sh
# Usage: sudo bash generate_certificate.sh --logdir /var/log/wipe_reports --key /media/usb/token.pem --outdir /media/usb/wipe_reports
#
# Produces:
#   certificate-<timestamp>.json
#   certificate-<timestamp>.json.sig   (openssl signature)
#   certificate-<timestamp>.pdf       (readable formatted certificate)
#
set -euo pipefail

LOGDIR=""
KEY_PATH=""
OUTDIR=""
OPERATOR="unknown"
AGENCY="WipeTool"
TIMESTAMP="$(date --iso-8601=seconds)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --logdir) LOGDIR="$2"; shift 2;;
    --key) KEY_PATH="$2"; shift 2;;
    --outdir) OUTDIR="$2"; shift 2;;
    --operator) OPERATOR="$2"; shift 2;;
    --agency) AGENCY="$2"; shift 2;;
    --help) sed -n '1,200p' "$0"; exit 0;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done

if [[ -z "$LOGDIR" ]]; then LOGDIR="/var/log/wipe_reports"; fi
if [[ -z "$OUTDIR" ]]; then
  # try to place on removable if present
  if compgen -G "/run/media/*/*" >/dev/null 2>&1; then
    OUTDIR=$(ls -d /run/media/*/* | head -n1)/wipe_reports
  elif compgen -G "/media/*" >/dev/null 2>&1; then
    OUTDIR="/media/$(ls /media | head -n1)/wipe_reports"
  else
    OUTDIR="$LOGDIR"
  fi
fi

mkdir -p "$OUTDIR"

if [[ ! -d "$LOGDIR" ]]; then
  echo "Log dir $LOGDIR not found"
  exit 2
fi

if [[ -n "$KEY_PATH" && ! -f "$KEY_PATH" ]]; then
  echo "Signing key $KEY_PATH not found"
  exit 2
fi

# gather logs and compute sha256 of concatenated logs
CERT_BASE="wipe_certificate_$(date --utc +%Y%m%dT%H%M%SZ)"
CERT_JSON="$OUTDIR/${CERT_BASE}.json"
CERT_SIG="$OUTDIR/${CERT_BASE}.json.sig"
CERT_PDF="$OUTDIR/${CERT_BASE}.pdf"

# Build a devices array from summary.log if present, else include raw logs
DEVICES_JSON="[]"
if [[ -f "$LOGDIR/summary.log" ]]; then
  # build JSON array of lines in summary.log (each line is JSON)
  DEVICES_JSON=$(jq -s '.' "$LOGDIR/summary.log" 2>/dev/null || true)
else
  # find any lines with device entries in logs
  DEVICES_JSON="[]"
fi

# compute combined log sha256
COMBINED_SHA=""
if compgen -G "$LOGDIR/*" >/dev/null 2>&1; then
  # concatenate filenames in stable order
  FILES=( $(ls -1 "$LOGDIR" | sort) )
  TMP="/tmp/wipe_logs_concat_$$.bin"
  : > "$TMP"
  for f in "${FILES[@]}"; do
    cat "$LOGDIR/$f" >> "$TMP"
  done
  COMBINED_SHA=$(sha256sum "$TMP" | awk '{print $1}')
  rm -f "$TMP"
else
  COMBINED_SHA="none"
fi

CERT_OBJ=$(jq -n \
  --arg ts "$TIMESTAMP" \
  --arg op "$OPERATOR" \
  --arg agency "$AGENCY" \
  --arg logdir "$LOGDIR" \
  --arg logsha "$COMBINED_SHA" \
  --argjson devices "$DEVICES_JSON" \
  '{
    certificate_generated_at: $ts,
    operator: $op,
    agency: $agency,
    log_directory: $logdir,
    log_sha256: $logsha,
    devices: $devices,
    notes: "This certificate summarizes sanitization actions recorded by the tool. Verify signature using public key corresponding to signer."
  }')

echo "$CERT_OBJ" | jq '.' > "$CERT_JSON"
chmod 644 "$CERT_JSON"
echo "Wrote certificate JSON -> $CERT_JSON"

if [[ -n "$KEY_PATH" ]]; then
  # create signature
  openssl dgst -sha256 -sign "$KEY_PATH" -out "$CERT_SIG" "$CERT_JSON"
  chmod 600 "$CERT_SIG"
  echo "Created detached signature -> $CERT_SIG"
  # also create a public cert export if it exists in same dir (optional)
fi

# create simple PDF for human readable (try enscript -> ps2pdf or pandoc)
if command -v enscript >/dev/null 2>&1 && command -v ps2pdf >/dev/null 2>&1; then
  echo "Creating PDF with enscript+ps2pdf"
  TMPTXT="/tmp/${CERT_BASE}.txt"
  echo "WIPE CERTIFICATE" > "$TMPTXT"
  echo "Generated: $TIMESTAMP" >> "$TMPTXT"
  echo "" >> "$TMPTXT"
  echo "Certificate JSON:" >> "$TMPTXT"
  echo "" >> "$TMPTXT"
  echo "$(jq -r '.' "$CERT_JSON")" >> "$TMPTXT"
  enscript -B -f Courier8 -p - "$TMPTXT" | ps2pdf - "$CERT_PDF"
  chmod 644 "$CERT_PDF"
  rm -f "$TMPTXT"
  echo "Created PDF -> $CERT_PDF"
elif command -v pandoc >/dev/null 2>&1; then
  echo "Creating PDF with pandoc"
  pandoc -o "$CERT_PDF" "$CERT_JSON" --from json
  echo "Created PDF -> $CERT_PDF"
else
  echo "PDF toolchain (enscript+ps2pdf or pandoc) not available. Only JSON/sig created."
fi

echo "Certificate generation complete."
echo "Files in $OUTDIR:"
ls -l "$OUTDIR/$CERT_BASE"* || true


