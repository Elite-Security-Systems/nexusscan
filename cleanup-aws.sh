#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}WARNING: This script will delete all NexusScan resources from your AWS account.${NC}"
echo -e "${YELLOW}All data will be permanently lost.${NC}"
read -p "Are you sure you want to continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Cleanup aborted.${NC}"
    exit 0
fi

echo -e "${YELLOW}Deleting CloudFormation stack...${NC}"
aws cloudformation delete-stack --stack-name nexusscan-stack

echo -e "${YELLOW}Waiting for stack deletion to complete (this may take several minutes)...${NC}"
aws cloudformation wait stack-delete-complete --stack-name nexusscan-stack

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Stack deleted successfully.${NC}"
else
    echo -e "${RED}Stack deletion failed or timed out. You may need to delete resources manually.${NC}"
fi

echo -e "${YELLOW}Cleaning up local configuration...${NC}"
if [ -f "nexusscan-config.sh" ]; then
    rm nexusscan-config.sh
fi

if [ -f "config.json" ]; then
    rm config.json
fi

echo -e "${GREEN}Cleanup completed!${NC}"
