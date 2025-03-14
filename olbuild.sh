#!/bin/bash

# Build script for NexusScan

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
mkdir -p dist/{scanner,scheduler,worker,processor,api}
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

# Add these lines to build.sh after the existing build commands

# Build enricher
echo "Building enricher..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/enricher/bootstrap cmd/enricher/main.go
(cd dist/enricher && zip -r ../enricher.zip bootstrap)

# Prepare httpx layer
echo "Preparing httpx layer..."
mkdir -p layers/httpx/bin
# Download httpx binary (this is a simplified example - in production you'd verify checksums)
curl -L -o layers/httpx/bin/httpx https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip
unzip layers/httpx/bin/httpx
chmod +x httpx
mv httpx layers/httpx/bin/

# Create directory structure for Lambda layer
mkdir -p layers/httpx/opt
mv layers/httpx/bin/httpx layers/httpx/opt/
(cd layers/httpx && zip -r httpx-layer.zip opt/)
mv layers/httpx/httpx-layer.zip dist/


echo "Build complete!"
