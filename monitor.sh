#!/bin/bash

# Monitoring script for NexusScan

echo "=== NexusScan Monitoring Report ==="
echo "Date: $(date)"
echo ""

# Get Lambda usage
lambda_invocations=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Invocations \
    --start-time "$(date -d '-24 hours' '+%Y-%m-%dT%H:%M:%S')" \
    --end-time "$(date '+%Y-%m-%dT%H:%M:%S')" \
    --period 86400 \
    --statistics Sum \
    --dimensions Name=FunctionName,Value=nexusscan-scanner \
    --query "Datapoints[0].Sum" \
    --output text)

# Get Lambda duration
lambda_duration=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Duration \
    --start-time "$(date -d '-24 hours' '+%Y-%m-%dT%H:%M:%S')" \
    --end-time "$(date '+%Y-%m-%dT%H:%M:%S')" \
    --period 86400 \
    --statistics Average \
    --dimensions Name=FunctionName,Value=nexusscan-scanner \
    --query "Datapoints[0].Average" \
    --output text)

# Get SQS message count
sqs_messages=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/SQS \
    --metric-name NumberOfMessagesReceived \
    --start-time "$(date -d '-24 hours' '+%Y-%m-%dT%H:%M:%S')" \
    --end-time "$(date '+%Y-%m-%dT%H:%M:%S')" \
    --period 86400 \
    --statistics Sum \
    --dimensions Name=QueueName,Value=nexusscan-tasks \
    --query "Datapoints[0].Sum" \
    --output text)

# Calculate GB-seconds
gb_seconds=$(echo "$lambda_invocations * $lambda_duration * 1 / 1000" | bc -l)

# Get DynamoDB usage
dynamodb_read_capacity=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/DynamoDB \
    --metric-name ConsumedReadCapacityUnits \
    --start-time "$(date -d '-24 hours' '+%Y-%m-%dT%H:%M:%S')" \
    --end-time "$(date '+%Y-%m-%dT%H:%M:%S')" \
    --period 86400 \
    --statistics Sum \
    --dimensions Name=TableName,Value=nexusscan-results \
    --query "Datapoints[0].Sum" \
    --output text)

# Print summary
echo "=== Resource Usage (Last 24 Hours) ==="
echo "Lambda Invocations: $lambda_invocations"
echo "Average Duration: ${lambda_duration}ms"
echo "Estimated GB-seconds: ${gb_seconds}"
echo "SQS Messages: $sqs_messages"
echo "DynamoDB Read Capacity: $dynamodb_read_capacity"

# Free tier limits
echo ""
echo "=== Free Tier Status ==="
echo "Monthly Free Tier: 1,000,000 invocations, 400,000 GB-seconds"

# Calculate percentage used (assuming 30-day month)
invocation_daily_limit=$((1000000 / 30))
gbseconds_daily_limit=$((400000 / 30))

invocation_percent=$(echo "scale=2; $lambda_invocations * 100 / $invocation_daily_limit" | bc -l)
gbseconds_percent=$(echo "scale=2; $gb_seconds * 100 / $gbseconds_daily_limit" | bc -l)

echo "Daily Invocation Usage: ${invocation_percent}%"
echo "Daily GB-seconds Usage: ${gbseconds_percent}%"

if (( $(echo "$invocation_percent > 80" | bc -l) )) || (( $(echo "$gbseconds_percent > 80" | bc -l) )); then
    echo "WARNING: Approaching free tier limits!"
    echo "Consider adjusting scan frequency or reducing concurrency."
fi

# List assets with open ports
echo ""
echo "=== Recent Open Ports Summary ==="
aws dynamodb scan \
    --table-name nexusscan-open-ports \
    --select SPECIFIC_ATTRIBUTES \
    --projection-expression "AssetId, OpenPorts" \
    --limit 10 \
    --query "Items" \
    --output table
