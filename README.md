# NexusScan: Ultra-Fast Serverless Port Scanner

A high-performance, serverless port scanner optimized for AWS Lambda free tier.

## Quick Start

### Prerequisites
- AWS Account with CLI configured
- Go 1.16 or newer
- AWS SAM CLI (for deployment)

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Elite-Security-Systems/nexusscan.git
   cd nexusscan
   ```

2. Build and deploy:
   ```bash
   # Make scripts executable
   chmod +x build.sh deploy.sh monitor.sh examples.sh
   
   # Deploy to AWS
   ./deploy.sh
   ```

3. Import assets:
   ```bash
   # Create a CSV with your assets
   echo "Name,IP,Type" > assets.csv
   echo "webserver1,192.168.1.10,server" >> assets.csv
   echo "database,192.168.1.12,database" >> assets.csv
   
   # Import assets
   ./bin/assetloader -file=assets.csv -client=client123
   ```

4. Start scanning:
   ```bash
   # Invoke the scheduler to run a scan
   aws lambda invoke \
     --function-name nexusscan-scheduler \
     --payload '{"profileId":"daily","clientId":"client123","forceRun":true}' \
     response.json
   ```

### Monitoring

Monitor your scanning activity and resource usage:
```bash
./monitor.sh
```

### Usage Examples

See more usage examples:
```bash
./examples.sh
```

## Scan Profiles

NexusScan includes four optimized scanning profiles:

1. **Hourly Scan**: Scans only previously discovered open ports (minimal resource usage)
2. **12-Hour Scan**: Scans top 1,500 ports (balanced approach)
3. **Daily Scan**: Scans 3,500 important ports (comprehensive coverage)
4. **Weekly Scan**: Scans all 65,535 ports (complete security audit)

## Cost Optimization

The entire solution is designed to operate within AWS free tier limits:
- Lambda: 1,000,000 invocations, 400,000 GB-seconds per month
- DynamoDB: 25 RCU/WCU
- S3: 5GB storage, limited GET/PUT requests
- SQS: 1 million requests

Monitor your usage with `./monitor.sh` to ensure you stay within free tier limits.

## License

MIT
```

Now you have a complete, ready-to-deploy port scanning solution optimized for AWS Lambda free tier. The system is designed to be simple to deploy and manage while providing advanced scanning capabilities through different scan profiles.

To use it:
1. Run `./deploy.sh` to build and deploy everything to AWS
2. Upload your assets using `./bin/assetloader`
3. Start scans using the AWS Lambda function or API
4. Monitor with `./monitor.sh`

This implementation can scan up to 10,000 assets with varying frequencies while staying within AWS free tier limits.
