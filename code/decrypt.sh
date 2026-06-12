#!/bin/bash
set -euo pipefail

echo "WARNING: These legacy shell scripts are deprecated. Use 'envault decrypt' instead." >&2

# Load only S3_BUCKET and KMS_ACCOUNT_ID from .env to avoid leaking other
# credentials to subprocesses
if [[ -f "../.env" ]]; then
    _s3_val="$(grep -E '^S3_BUCKET=' "../.env" | head -1 | cut -d= -f2-)"
    [[ -n "${_s3_val}" ]] && S3_BUCKET="${_s3_val}"
    unset _s3_val
    _acct_val="$(grep -E '^KMS_ACCOUNT_ID=' "../.env" | head -1 | cut -d= -f2-)"
    [[ -n "${_acct_val}" ]] && KMS_ACCOUNT_ID="${_acct_val}"
    unset _acct_val
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

# Validate KMS_ACCOUNT_ID — constrains KMS discovery so we only ever call
# kms:Decrypt against keys in our own account, never one named by an
# attacker-supplied ciphertext header.
if [[ ! "${KMS_ACCOUNT_ID:-}" =~ ^[0-9]{12}$ ]]; then
    log "ERROR: KMS_ACCOUNT_ID is not set or not a 12-digit AWS account ID. Configure it in .env"
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

# Run decryption. Wrapping keys are passed here (not in decrypt.conf) so the
# discovery filter can be bound to the account ID loaded from .env.
if ! aws-encryption-cli @decrypt.conf \
    --wrapping-keys "discovery=true" "discovery-account=${KMS_ACCOUNT_ID}" "discovery-partition=aws" \
    -i "$INPUT_DIR" -r -o "$OUTPUT_DIR"; then
    log "ERROR: Decryption failed"
    exit 1
fi
log "Decryption completed successfully"

# Move encrypted input files to trash instead of deleting
TRASH_DIR="../.trash/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TRASH_DIR"
log "Moving processed encrypted files to $TRASH_DIR..."
find "$INPUT_DIR" -type f -exec mv {} "$TRASH_DIR/" \; 2>/dev/null || true

log "Decryption workflow completed successfully"
log "Decrypted files are in: $OUTPUT_DIR"
