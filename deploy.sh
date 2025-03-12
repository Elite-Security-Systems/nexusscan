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

# Check if samconfig.toml exists (indicates previous guided deployment)
if [ -f "samconfig.toml" ]; then
    echo "Deploying with existing configuration..."
    sam deploy
else
    echo "First deployment - running guided setup..."
    sam deploy --guided
fi

# Store outputs in environment file if deployment was successful
if [ $? -eq 0 ]; then
    echo "Storing configuration..."
    aws cloudformation describe-stacks \
        --stack-name nexusscan-stack \
        --query 'Stacks[0].Outputs' \
        --output json > config.json
    
    echo "Deployment complete!"
    
    # Extract and display API endpoint
    API_ENDPOINT=$(jq -r '.[] | select(.OutputKey == "ApiEndpoint") | .OutputValue' config.json)
    echo "API Endpoint: $API_ENDPOINT"
else
    echo "Deployment failed."
fi
