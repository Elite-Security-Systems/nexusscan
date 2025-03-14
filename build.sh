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
mkdir -p layers/httpx/opt

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

# Download httpx
HTTPX_VERSION="1.6.10"
HTTPX_ZIP="httpx_${HTTPX_VERSION}_linux_amd64.zip"
HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/${HTTPX_ZIP}"

echo "Downloading httpx v${HTTPX_VERSION}..."
curl -L -o "$HTTPX_ZIP" "$HTTPX_URL"

# Extract the httpx binary directly into the layer directory
echo "Extracting httpx..."
unzip -j "$HTTPX_ZIP" "httpx" -d "layers/httpx/opt/"
chmod +x "layers/httpx/opt/httpx"

# Check if the binary is there and executable
if [ ! -x "layers/httpx/opt/httpx" ]; then
  echo "Error: httpx binary is not executable or missing"
  exit 1
else
  echo "Verified httpx binary is executable at layers/httpx/opt/httpx"
  ls -la "layers/httpx/opt/httpx"
fi

# Create a simple shell script wrapper to help with troubleshooting
cat > "layers/httpx/opt/httpx-wrapper.sh" << 'EOF'
#!/bin/bash
echo "httpx-wrapper.sh called with args: $@" >> /tmp/httpx-debug.log
export PATH=$PATH:/opt:/opt/bin
which httpx >> /tmp/httpx-debug.log 2>&1
/opt/httpx "$@"
EOF
chmod +x "layers/httpx/opt/httpx-wrapper.sh"

# Create the layer ZIP file
echo "Creating httpx layer ZIP file"
(cd layers/httpx && zip -r ../../dist/httpx-layer.zip opt)

# Clean up
rm "$HTTPX_ZIP"

echo "Build complete!"
