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

# Create output directories
mkdir -p dist

# Build scanner
echo "Building scanner..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/scanner/bootstrap cmd/scanner/main.go
cd dist/scanner && zip -r ../scanner.zip bootstrap && cd ../..

# Build scheduler
echo "Building scheduler..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/scheduler/bootstrap cmd/scheduler/main.go
cd dist/scheduler && zip -r ../scheduler.zip bootstrap && cd ../..

# Build worker
echo "Building worker..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/worker/bootstrap cmd/worker/main.go
cd dist/worker && zip -r ../worker.zip bootstrap && cd ../..

# Build processor
echo "Building processor..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/processor/bootstrap cmd/processor/main.go
cd dist/processor && zip -r ../processor.zip bootstrap && cd ../..

# Build API
echo "Building API..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/api/bootstrap cmd/api/main.go
cd dist/api && zip -r ../api.zip bootstrap && cd ../..

# Build asset loader
echo "Building asset loader..."
go build -o bin/assetloader cmd/assetloader/main.go

echo "Build complete!"
