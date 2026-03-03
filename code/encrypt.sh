#!/bin/bash
set -euo pipefail

# Load environment variables if .env exists
if [[ -f "../.env" ]]; then
    set -a
    . "../.env"
    set +a
fi

INPUT_DIR="../encrypt"
OUTPUT_DIR="../encrypted"
LOG_FILE="../logs/encryption.log"

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
    log "WARNING: Input directory $INPUT_DIR is empty, nothing to encrypt"
    exit 0
fi

log "Starting encryption..."

# Run encryption
if ! aws-encryption-cli @encrypt.conf -i "$INPUT_DIR" -r -o "$OUTPUT_DIR"; then
    log "ERROR: Encryption failed"
    exit 1
fi
log "Encryption completed successfully"

# Sync to S3
log "Syncing encrypted files to S3..."
if ! aws s3 sync "$OUTPUT_DIR" "s3://${S3_BUCKET}/encrypted"; then
    log "ERROR: S3 sync failed for encrypted files"
    exit 1
fi

# Clean up local encrypted files
log "Cleaning up local encrypted files..."
find "$OUTPUT_DIR" -type f -delete 2>/dev/null || true

# Sync code directory
log "Syncing code directory to S3..."
aws s3 sync ../code "s3://${S3_BUCKET}/code"

log "Encryption workflow completed successfully"
