#!/bin/bash
set -euo pipefail

# Load environment variables if .env exists
if [[ -f "../.env" ]]; then
    set -a
    . "../.env"
    set +a
fi

INPUT_DIR="../decrypt"
OUTPUT_DIR="../decrypted"
LOG_FILE="../logs/decryption.log"

# Create logs directory if it doesn't exist
mkdir -p "../logs"

log() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG_FILE"
}

# Validate S3_BUCKET is set
if [[ -z "${S3_BUCKET:-}" ]]; then
    log "ERROR: S3_BUCKET is not set. Configure it in .env"
    exit 1
fi

# Validate input directory
if [[ ! -d "$INPUT_DIR" ]]; then
    log "ERROR: Input directory $INPUT_DIR does not exist"
    exit 1
fi

if [[ -z "$(ls -A "$INPUT_DIR" 2>/dev/null)" ]]; then
    log "WARNING: Input directory $INPUT_DIR is empty, nothing to decrypt"
    exit 0
fi

log "Starting decryption..."

# Run decryption
if ! aws-encryption-cli @decrypt.conf -i "$INPUT_DIR" -r -o "$OUTPUT_DIR"; then
    log "ERROR: Decryption failed"
    exit 1
fi
log "Decryption completed successfully"

# Move encrypted input files to trash instead of deleting
TRASH_DIR="../.trash/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TRASH_DIR"
log "Moving processed encrypted files to $TRASH_DIR..."
find "$INPUT_DIR" -type f -exec mv {} "$TRASH_DIR/" \; 2>/dev/null || true

# Sync code directory
log "Syncing code directory to S3..."
aws s3 sync ../code "s3://${S3_BUCKET}/code"

log "Decryption workflow completed successfully"
log "Decrypted files are in: $OUTPUT_DIR"
