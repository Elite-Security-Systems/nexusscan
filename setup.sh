#!/bin/bash

set -e

# Verify prerequisites
check_prerequisite() {
    if ! command -v $1 &> /dev/null; then
        echo "Error: $1 is required but not installed. Please install it first."
        exit 1
    fi
}

check_prerequisite "aws"
check_prerequisite "jq"
check_prerequisite "go"
check_prerequisite "sam"

# Configuration
USER="admin"
PASSWORD="6x1mcv1xXn1^"  # You should change this in production
EMAIL="your-email@example.com"  # Change this to your email

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building NexusScan components...${NC}"
./build.sh

echo -e "${YELLOW}Deploying to AWS...${NC}"
./deploy.sh

# Extract configuration
echo -e "${YELLOW}Extracting configuration...${NC}"
USER_POOL_ID=$(jq -r '.[] | select(.OutputKey == "UserPoolId") | .OutputValue' config.json)
CLIENT_ID=$(jq -r '.[] | select(.OutputKey == "UserPoolClientId") | .OutputValue' config.json)
API_ENDPOINT=$(jq -r '.[] | select(.OutputKey == "ApiEndpoint") | .OutputValue' config.json)

# Save configuration for later use
echo -e "${YELLOW}Saving configuration to nexusscan-config.sh...${NC}"
echo "export USER_POOL_ID=\"$USER_POOL_ID\"" > nexusscan-config.sh
echo "export CLIENT_ID=\"$CLIENT_ID\"" >> nexusscan-config.sh
echo "export API_ENDPOINT=\"$API_ENDPOINT\"" >> nexusscan-config.sh
echo "export USER=\"$USER\"" >> nexusscan-config.sh
echo "export PASSWORD=\"$PASSWORD\"" >> nexusscan-config.sh

echo -e "${YELLOW}Creating admin user...${NC}"
# Check if user already exists
USER_EXISTS=$(aws cognito-idp admin-get-user --user-pool-id $USER_POOL_ID --username $USER 2>&1 || echo "NOT_FOUND")

if [[ $USER_EXISTS == *"NOT_FOUND"* ]]; then
    # Create user
    aws cognito-idp admin-create-user \
      --user-pool-id $USER_POOL_ID \
      --username $USER \
      --temporary-password "$PASSWORD" \
      --user-attributes Name=email,Value=$EMAIL

    # Set permanent password
    aws cognito-idp admin-set-user-password \
      --user-pool-id $USER_POOL_ID \
      --username $USER \
      --password "$PASSWORD" \
      --permanent
else
    echo -e "${YELLOW}User already exists. Skipping user creation.${NC}"
fi

echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "Run the following command to load the environment variables:"
echo -e "${GREEN}source nexusscan-config.sh${NC}"
