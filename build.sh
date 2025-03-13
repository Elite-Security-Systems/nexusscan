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

echo "Build complete!"
