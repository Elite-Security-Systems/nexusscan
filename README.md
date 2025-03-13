# NexusScan

A distributed, scalable port scanning system built with AWS serverless architecture. NexusScan allows you to monitor open ports across multiple IP addresses with configurable scanning schedules and comprehensive result tracking.

## Features

- **Flexible Port Scanning**: Scan with predefined port sets or previously discovered open ports
- **Scheduling System**: Configure hourly, 12-hour, daily, weekly, or monthly scans
- **Distributed Architecture**: Handles large numbers of IPs and ports efficiently
- **Comprehensive API**: RESTful endpoints for all operations
- **Secure Authentication**: Protected with AWS Cognito

## Architecture

NexusScan uses AWS serverless components:

- **Lambda Functions**: Scanner, Scheduler, Worker, Processor, API
- **DynamoDB**: For storing IP information, schedules, and scan results
- **SQS Queues**: For distributing scanning tasks
- **API Gateway**: For exposing the RESTful API
- **Cognito**: For user authentication

## Setup & Deployment

### Prerequisites

- AWS CLI installed and configured
- AWS SAM CLI installed
- Go 1.19 or later
- jq (for JSON processing)

### Deployment Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/Elite-Security-Systems/nexusscan.git
   cd nexusscan
   ```

2. Build the Lambda functions:
   ```bash
   ./build.sh
   ```

3. Deploy to AWS:
   ```bash
   ./deploy.sh
   ```

4. Create an admin user:
   ```bash
   # Extract configuration values
   USER_POOL_ID=$(jq -r '.[] | select(.OutputKey == "UserPoolId") | .OutputValue' config.json)
   CLIENT_ID=$(jq -r '.[] | select(.OutputKey == "UserPoolClientId") | .OutputValue' config.json)
   API_ENDPOINT=$(jq -r '.[] | select(.OutputKey == "ApiEndpoint") | .OutputValue' config.json)
   
   # Create admin user
   aws cognito-idp admin-create-user \
     --user-pool-id $USER_POOL_ID \
     --username admin \
     --temporary-password "YourSecurePassword123!" \
     --user-attributes Name=email,Value=your-email@example.com
   
   # Set permanent password
   aws cognito-idp admin-set-user-password \
     --user-pool-id $USER_POOL_ID \
     --username admin \
     --password "YourSecurePassword123!" \
     --permanent
   ```

5. Get an authentication token (required for all API calls):
   ```bash
   TOKEN=$(aws cognito-idp initiate-auth \
     --client-id "$CLIENT_ID" \
     --auth-flow USER_PASSWORD_AUTH \
     --auth-parameters USERNAME="admin",PASSWORD="YourSecurePassword123!" \
     --region us-east-1 | jq -r '.AuthenticationResult.IdToken')
   ```

### Simplified Setup Script

Create a file called `setup.sh` with the following content:

```bash
#!/bin/bash

# Build and deploy
./build.sh
./deploy.sh

# Create admin user
USER="admin"
PASSWORD="YourSecurePassword123!"
EMAIL="your-email@example.com"

# Extract configuration
USER_POOL_ID=$(jq -r '.[] | select(.OutputKey == "UserPoolId") | .OutputValue' config.json)
CLIENT_ID=$(jq -r '.[] | select(.OutputKey == "UserPoolClientId") | .OutputValue' config.json)
API_ENDPOINT=$(jq -r '.[] | select(.OutputKey == "ApiEndpoint") | .OutputValue' config.json)

# Save configuration for later use
echo "export USER_POOL_ID=\"$USER_POOL_ID\"" > nexusscan-config.sh
echo "export CLIENT_ID=\"$CLIENT_ID\"" >> nexusscan-config.sh
echo "export API_ENDPOINT=\"$API_ENDPOINT\"" >> nexusscan-config.sh
echo "export USER=\"$USER\"" >> nexusscan-config.sh
echo "export PASSWORD=\"$PASSWORD\"" >> nexusscan-config.sh

# Create user
aws cognito-idp admin-create-user \
  --user-pool-id $USER_POOL_ID \
  --username $USER \
  --temporary-password "$PASSWORD" \
  --user-attributes Name=email,Value=$EMAIL

aws cognito-idp admin-set-user-password \
  --user-pool-id $USER_POOL_ID \
  --username $USER \
  --password "$PASSWORD" \
  --permanent

echo "Setup completed successfully."
echo "Run 'source nexusscan-config.sh' to load the environment variables."
```

Make it executable and run:
```bash
chmod +x setup.sh
./setup.sh
source nexusscan-config.sh
```

### Testing Script

Create a file called `test.sh` with the following content:

```bash
#!/bin/bash

# Source configuration
source nexusscan-config.sh

# Get token
TOKEN=$(aws cognito-idp initiate-auth \
  --client-id "$CLIENT_ID" \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="$USER",PASSWORD="$PASSWORD" \
  --region us-east-1 | jq -r '.AuthenticationResult.IdToken')

# Test IP for scanning
TEST_IP="1.1.1.1"

# API Tests
echo "Adding IP..."
curl -s -X POST "${API_ENDPOINT}api/ip" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{ \"ip\": \"$TEST_IP\"}" | jq .

echo "Scheduling immediate scan..."
curl -s -X POST "${API_ENDPOINT}api/scan" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{ \"ip\": \"$TEST_IP\", \"portSet\": \"top_100\", \"immediate\": true }" | jq .

echo "Waiting for scan to complete (10 seconds)..."
sleep 10

echo "Getting scan results..."
curl -s -X GET "${API_ENDPOINT}api/scan-results/$TEST_IP" -H "Authorization: Bearer $TOKEN" | jq .

echo "Getting open ports..."
curl -s -X GET "${API_ENDPOINT}api/open-ports/$TEST_IP" -H "Authorization: Bearer $TOKEN" | jq .

echo "Test completed."
```

Make it executable and run:
```bash
chmod +x test.sh
./test.sh
```

## API Reference

All API calls require an Authorization header with a valid Cognito token:
```
Authorization: Bearer YOUR_ID_TOKEN
```

### Authentication

```bash
# Get authentication token
TOKEN=$(aws cognito-idp initiate-auth \
  --client-id "$CLIENT_ID" \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="admin",PASSWORD="YourPassword" \
  --region us-east-1 | jq -r '.AuthenticationResult.IdToken')
```

### IP Management

#### Add a single IP

```bash
curl -X POST "${API_ENDPOINT}api/ip" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "ip": "192.168.1.1" }'
```

#### Add multiple IPs

```bash
curl -X POST "${API_ENDPOINT}api/ips" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "ips": ["192.168.1.1", "192.168.1.2", "192.168.1.3"] }'
```

#### Get all IPs (with pagination)

```bash
curl -X GET "${API_ENDPOINT}api/ips?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

#### Delete an IP

```bash
curl -X DELETE "${API_ENDPOINT}api/ip" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "ip": "192.168.1.1" }'
```

### Schedule Management

#### Add a scan schedule

```bash
curl -X POST "${API_ENDPOINT}api/schedule" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "scheduleType": "daily",
    "portSet": "top_100",
    "enabled": true
  }'
```

#### Add schedules for multiple IPs

```bash
curl -X POST "${API_ENDPOINT}api/schedules" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1", "192.168.1.2"],
    "scheduleType": "daily",
    "portSet": "top_100",
    "enabled": true
  }'
```

#### Get schedules for an IP

```bash
curl -X GET "${API_ENDPOINT}api/schedules/192.168.1.1" \
  -H "Authorization: Bearer $TOKEN"
```

#### Update schedule status (enable/disable)

```bash
curl -X PUT "${API_ENDPOINT}api/schedule-status" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "scheduleType": "daily",
    "enabled": false
  }'
```

#### Delete a schedule

```bash
curl -X DELETE "${API_ENDPOINT}api/schedule" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "scheduleType": "daily"
  }'
```

### Scan Management

#### Start an immediate scan

```bash
curl -X POST "${API_ENDPOINT}api/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "portSet": "top_100",
    "immediate": true
  }'
```

Available port sets:
- `previous_open`: Only scan ports previously found open
- `top_100`: Scan the top 100 most common ports
- `custom_3500`: Scan ~3500 commonly used ports
- `full_65k`: Scan all 65,535 ports (takes much longer)

#### Start a bulk scan for multiple IPs

```bash
curl -X POST "${API_ENDPOINT}api/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1", "192.168.1.2"],
    "portSet": "top_100",
    "immediate": true
  }'
```

#### Get scan results

```bash
curl -X GET "${API_ENDPOINT}api/scan-results/192.168.1.1?limit=5" \
  -H "Authorization: Bearer $TOKEN"
```

#### Get open ports

```bash
curl -X GET "${API_ENDPOINT}api/open-ports/192.168.1.1" \
  -H "Authorization: Bearer $TOKEN"
```

## Clean Up

To remove all resources created by NexusScan:

```bash
aws cloudformation delete-stack --stack-name nexusscan-stack
aws cloudformation wait stack-delete-complete --stack-name nexusscan-stack
```
