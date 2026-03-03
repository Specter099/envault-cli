.PHONY: encrypt decrypt clean setup help dirs logs-clean trash-clean

# Default target
help:
	@echo "AWS Encryption Automation"
	@echo ""
	@echo "Usage:"
	@echo "  make setup      - Create required directories"
	@echo "  make encrypt    - Encrypt files in encrypt/ directory"
	@echo "  make decrypt    - Decrypt files in decrypt/ directory"
	@echo "  make clean      - Remove output directories (encrypted/decrypted)"
	@echo "  make logs-clean - Remove log files"
	@echo "  make trash-clean- Remove trash directory"
	@echo "  make dirs       - Show directory status"
	@echo ""
	@echo "Directories:"
	@echo "  encrypt/   - Place files here to encrypt"
	@echo "  decrypt/   - Place encrypted files here to decrypt"
	@echo "  encrypted/ - Encrypted output (temporary)"
	@echo "  decrypted/ - Decrypted output"

# Create required directories
setup:
	@mkdir -p encrypt decrypt encrypted decrypted logs .trash
	@echo "Directories created successfully"
	@if [ ! -f .env ]; then \
		cp .env.example .env 2>/dev/null && echo "Created .env from .env.example - please edit with your values" || true; \
	fi

# Run encryption workflow
encrypt:
	@cd code && ./encrypt.sh

# Run decryption workflow
decrypt:
	@cd code && ./decrypt.sh

# Show directory status
dirs:
	@echo "=== Directory Status ==="
	@echo "encrypt/:"
	@ls -la encrypt/ 2>/dev/null || echo "  (directory does not exist)"
	@echo ""
	@echo "decrypt/:"
	@ls -la decrypt/ 2>/dev/null || echo "  (directory does not exist)"
	@echo ""
	@echo "encrypted/:"
	@ls -la encrypted/ 2>/dev/null || echo "  (directory does not exist)"
	@echo ""
	@echo "decrypted/:"
	@ls -la decrypted/ 2>/dev/null || echo "  (directory does not exist)"

# Clean output directories
clean:
	@rm -rf encrypted/* decrypted/*
	@echo "Output directories cleaned"

# Clean log files
logs-clean:
	@rm -rf logs/*
	@echo "Logs cleaned"

# Clean trash directory
trash-clean:
	@rm -rf .trash/*
	@echo "Trash cleaned"
