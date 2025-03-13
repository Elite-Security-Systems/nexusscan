#!/bin/bash

# Check if config is loaded
if [[ -z "$USER_POOL_ID" || -z "$CLIENT_ID" || -z "$API_ENDPOINT" || -z "$USER" || -z "$PASSWORD" ]]; then
    if [[ -f "nexusscan-config.sh" ]]; then
        echo "Loading configuration from nexusscan-config.sh..."
        source nexusscan-config.sh
    else
        echo "Error: Configuration not found. Please run setup.sh first."
        exit 1
    fi
fi

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get authentication token
echo -e "${YELLOW}Authenticating...${NC}"
TOKEN=$(aws cognito-idp initiate-auth \
  --client-id "$CLIENT_ID" \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="$USER",PASSWORD="$PASSWORD" \
  --region us-east-1 | jq -r '.AuthenticationResult.IdToken')

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo -e "${RED}Authentication failed. Please check your credentials.${NC}"
    exit 1
fi

echo -e "${GREEN}Authentication successful!${NC}"

# Test IP for scanning
TEST_IP="1.1.1.1"

# Function for API calls
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    echo -e "${YELLOW}$4${NC}"
    
    local response
    if [[ -n "$data" ]]; then
        response=$(curl -s -X $method "${API_ENDPOINT}$endpoint" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data")
    else
        response=$(curl -s -X $method "${API_ENDPOINT}$endpoint" \
            -H "Authorization: Bearer $TOKEN")
    fi
    
    echo "$response" | jq .
    echo ""
}

# API Tests
api_call "POST" "api/ip" "{ \"ip\": \"$TEST_IP\"}" "Adding IP..."

api_call "POST" "api/schedule" "{ \"ip\": \"$TEST_IP\", \"scheduleType\": \"daily\", \"portSet\": \"top_100\", \"enabled\": true }" "Adding daily schedule..."

api_call "GET" "api/schedules/$TEST_IP" "" "Getting schedules for IP..."

api_call "POST" "api/scan" "{ \"ip\": \"$TEST_IP\", \"portSet\": \"top_100\", \"immediate\": true }" "Starting immediate scan..."

echo -e "${YELLOW}Waiting for scan to complete (15 seconds)...${NC}"
for i in {1..15}; do
    echo -n "."
    sleep 1
done
echo ""

api_call "GET" "api/scan-results/$TEST_IP" "" "Getting scan results..."

api_call "GET" "api/open-ports/$TEST_IP" "" "Getting open ports..."

api_call "PUT" "api/schedule-status" "{ \"ip\": \"$TEST_IP\", \"scheduleType\": \"daily\", \"enabled\": false }" "Disabling daily schedule..."

echo -e "${GREEN}Test completed successfully!${NC}"
echo -e "To clean up this test IP, run:"
echo -e "${GREEN}./cleanup-test.sh${NC}"
