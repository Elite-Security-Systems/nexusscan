# NexusScan: Ultra-Fast Serverless Port Scanner

A high-performance, serverless port scanner built on AWS Lambda that efficiently discovers open ports across your network assets.

## Overview

NexusScan provides a scalable, cost-efficient port scanning solution that leverages AWS serverless architecture to scan thousands of IP addresses without maintaining dedicated infrastructure. The system is designed to work within AWS free tier limits while providing enterprise-grade scanning capabilities.

## Architecture

NexusScan uses a distributed, event-driven architecture:

- **API Gateway**: Provides RESTful endpoints for managing IPs, schedules, and scans
- **Lambda Functions**: Serverless compute for API, scanning, processing, and scheduling
- **DynamoDB**: Stores IPs, schedules, scan results, and open ports
- **SQS Queues**: Manages scan tasks and results processing
- **Cognito**: Handles authentication

## Features

- **Flexible Scan Profiles**: Choose from predefined port sets or scan previously discovered open ports
- **Scheduled Scanning**: Configure hourly, 12-hour, daily, weekly, or monthly scans
- **Batch Processing**: Efficiently distributes large port ranges across multiple Lambda functions
- **Result Aggregation**: Consolidates batch results for a comprehensive view
- **Open Port Tracking**: Maintains history of discovered open ports

## Deployment

### Prerequisites
- AWS Account with CLI configured
- Go 1.16 or newer
- AWS SAM CLI

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/nexusscan.git
   cd nexusscan
   ```

2. Make scripts executable:
   ```bash
   chmod +x build.sh deploy.sh monitor.sh examples.sh
   ```

3. Build and deploy:
   ```bash
   ./build.sh
   ./deploy.sh
   ```

4. After deployment, the script will output the API endpoint and Cognito details needed for authentication.

## Usage

### Authentication

1. Create a user in the Cognito User Pool:
   ```bash
   aws cognito-idp admin-create-user \
     --user-pool-id YOUR_USER_POOL_ID \
     --username admin \
     --temporary-password "Temp1234!"
   ```

2. Set a permanent password:
   ```bash
   aws cognito-idp admin-set-user-password \
     --user-pool-id YOUR_USER_POOL_ID \
     --username admin \
     --password "YourSecurePassword123!" \
     --permanent
   ```

3. Get an authentication token:
   ```bash
   aws cognito-idp initiate-auth \
     --auth-flow USER_PASSWORD_AUTH \
     --client-id YOUR_CLIENT_ID \
     --auth-parameters USERNAME=admin,PASSWORD="YourSecurePassword123!" \
     --query "AuthenticationResult.IdToken" \
     --output text
   ```

4. Store the token for API requests:
   ```bash
   export TOKEN="YOUR_ID_TOKEN"
   ```

### API Examples

#### Add an IP to scan:
```bash
curl -X POST "${API_ENDPOINT}api/ip" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1"}'
```

#### Set up a scheduled scan:
```bash
curl -X POST "${API_ENDPOINT}api/schedule" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "scheduleType": "daily",
    "portSet": "custom_3500",
    "enabled": true
  }'
```

#### Run an immediate scan:
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

#### Get open ports:
```bash
curl -X GET "${API_ENDPOINT}api/open-ports/192.168.1.1" \
  -H "Authorization: Bearer $TOKEN"
```

#### Get scan results:
```bash
curl -X GET "${API_ENDPOINT}api/scan-results/192.168.1.1" \
  -H "Authorization: Bearer $TOKEN"
```

## Port Sets

The system includes several predefined port sets:

- **previous_open**: Only scans previously discovered open ports
- **top_100**: Scans the 100 most common ports
- **custom_3500**: Scans approximately 3,500 important ports
- **full_65k**: Scans all 65,535 ports (resource intensive)

## Schedule Types

Available schedule frequencies:

- **hourly**: Runs once every hour
- **12hour**: Runs once every 12 hours
- **daily**: Runs once per day
- **weekly**: Runs once per week
- **monthly**: Runs once every 30 days

## Monitoring

Monitor your scanning activity:
```bash
./monitor.sh
```

## Cost Optimization

NexusScan is designed to operate within AWS free tier limits:
- Lambda: 1,000,000 invocations, 400,000 GB-seconds per month
- DynamoDB: 25 RCU/WCU
- SQS: 1 million requests

The architecture allows scaling to thousands of IPs while maintaining cost efficiency.

## Support and Contribution

For issues, feature requests, or contributions, please open an issue or pull request in the repository.

## Security Considerations

NexusScan is designed for legitimate security testing and network monitoring. Always ensure you have permission to scan the target IP addresses. Unauthorized port scanning may violate laws and terms of service.
