#!/bin/bash

# Build script for NexusScan with httpx integration

# Function to clean up on error
cleanup() {
  echo "Error occurred, cleaning up..."
  exit 1
}

# Set up error handling
trap cleanup ERR

# Set environment
export GO111MODULE=on
export CGO_ENABLED=0

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go before continuing."
    exit 1
fi

echo "Building NexusScan components..."

# Create output directories - make sure they exist first
mkdir -p dist/{scanner,scheduler,worker,processor,api,enricher}
mkdir -p bin

# Build scanner
echo "Building scanner..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/scanner/bootstrap cmd/scanner/main.go
(cd dist/scanner && zip -r ../scanner.zip bootstrap)

# Build scheduler
echo "Building scheduler..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/scheduler/bootstrap cmd/scheduler/main.go
(cd dist/scheduler && zip -r ../scheduler.zip bootstrap)

# Build worker
echo "Building worker..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/worker/bootstrap cmd/worker/main.go
(cd dist/worker && zip -r ../worker.zip bootstrap)

# Build processor
echo "Building processor..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/processor/bootstrap cmd/processor/main.go
(cd dist/processor && zip -r ../processor.zip bootstrap)

# Build API
echo "Building API..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/api/bootstrap cmd/api/main.go
(cd dist/api && zip -r ../api.zip bootstrap)

# Build enricher
echo "Building enricher..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/enricher/bootstrap cmd/enricher/main.go
(cd dist/enricher && zip -r ../enricher.zip bootstrap)

# Prepare httpx layer
echo "Preparing httpx layer..."

# Create a clean directory structure for the layer
rm -rf layers
mkdir -p layers/bin

# Download httpx
HTTPX_VERSION="1.6.10"
HTTPX_ZIP="httpx_${HTTPX_VERSION}_linux_amd64.zip"
HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/${HTTPX_ZIP}"

echo "Downloading httpx v${HTTPX_VERSION}..."
curl -s -L -o "$HTTPX_ZIP" "$HTTPX_URL"

# Extract the httpx binary directly into multiple locations for redundancy
echo "Extracting httpx..."
unzip -j "$HTTPX_ZIP" "httpx" -d "layers/bin/"
chmod +x "layers/bin/httpx"

# Create a simple shell script to find and execute httpx
cat > "layers/bin/find-httpx.sh" << 'EOF'
#!/bin/bash
# This script attempts to find and execute httpx
LOG_FILE="/tmp/httpx-debug.log"

echo "$(date): find-httpx.sh called with args: $@" >> $LOG_FILE
echo "PATH=$PATH" >> $LOG_FILE

# Search in common locations
POSSIBLE_PATHS=(
  "/opt/httpx"
  "/opt/bin/httpx"
  "/var/task/httpx"
  "/var/runtime/httpx"
  "/var/lang/bin/httpx"
  "/tmp/httpx"
)

HTTPX_PATH=""
for path in "${POSSIBLE_PATHS[@]}"; do
  if [ -x "$path" ]; then
    HTTPX_PATH="$path"
    echo "Found httpx at: $HTTPX_PATH" >> $LOG_FILE
    break
  fi
done

# If not found, try using which
if [ -z "$HTTPX_PATH" ]; then
  HTTPX_PATH=$(which httpx 2>/dev/null)
  echo "which httpx result: $HTTPX_PATH" >> $LOG_FILE
fi

# If still not found, try copying it to /tmp and using that
if [ -z "$HTTPX_PATH" ] || [ ! -x "$HTTPX_PATH" ]; then
  if [ -f "/var/task/bin/httpx" ]; then
    cp /var/task/bin/httpx /tmp/httpx
    chmod +x /tmp/httpx
    HTTPX_PATH="/tmp/httpx"
    echo "Copied httpx to /tmp" >> $LOG_FILE
  fi
fi

# Final execution
if [ -n "$HTTPX_PATH" ] && [ -x "$HTTPX_PATH" ]; then
  echo "Executing: $HTTPX_PATH $@" >> $LOG_FILE
  "$HTTPX_PATH" "$@"
  exit $?
else
  echo "ERROR: httpx not found in any location" >> $LOG_FILE
  exit 1
fi
EOF
chmod +x "layers/bin/find-httpx.sh"

# Create the layer ZIP file - this now puts files at the root level
echo "Creating httpx layer ZIP file"
(cd layers && zip -r ../dist/httpx-layer.zip bin)

# Clean up
rm "$HTTPX_ZIP"

echo "Build complete!"
