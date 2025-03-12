#!/bin/bash

# Deployment script for NexusScan

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI not found. Please install it first."
    exit 1
fi

# Check SAM CLI
if ! command -v sam &> /dev/null; then
    echo "Error: AWS SAM CLI not found. Please install it first."
    exit 1
fi

# Build the project
./build.sh

# Deploy with SAM
echo "Deploying with SAM..."
sam deploy \
    --template-file template.yaml \
    --stack-name nexusscan-stack \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides \
        MemorySize=1024 \
        MaxConcurrentScans=100

# Store outputs in environment file
echo "Storing configuration..."
aws cloudformation describe-stacks \
    --stack-name nexusscan-stack \
    --query 'Stacks[0].Outputs' \
    --output json > config.json

echo "Deployment complete!"
echo "API Endpoint: $(jq -r '.[] | select(.OutputKey == "ApiEndpoint") | .OutputValue' config.json)"
