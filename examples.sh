#!/bin/bash

# Usage examples for NexusScan

# Get configuration
if [ ! -f config.json ]; then
    echo "Config file not found. Run deploy.sh first."
    exit 1
fi

API_ENDPOINT=$(jq -r '.[] | select(.OutputKey == "ApiEndpoint") | .OutputValue' config.json)

echo "=== NexusScan Usage Examples ==="
echo "API Endpoint: $API_ENDPOINT"
echo ""

# Example 1: Import assets
echo "Example 1: Import assets from CSV"
echo "---------------------------------"
echo "# First, create a CSV file with your assets:"
echo "Name,IP,Type"
echo "webserver1,192.168.1.10,server"
echo "loadbalancer,192.168.1.11,network"
echo "database,192.168.1.12,server"
echo ""
echo "# Then import using the asset loader:"
echo "./bin/assetloader -file=assets.csv -client=client123"
echo ""

# Example 2: Run a scan via API
echo "Example 2: Start a scan via API"
echo "-------------------------------"
echo "# To run a scan for a specific client:"
curl_command="curl -X POST \"${API_ENDPOINT}api/scan\" \\
  -H \"Content-Type: application/json\" \\
  -d '{\"clientId\":\"client123\",\"profileId\":\"daily\"}'"
echo "$curl_command"
echo ""
echo "# Expected response:"
echo "{\"message\":\"Scan scheduled successfully\",\"clientId\":\"client123\",\"profileId\":\"daily\"}"
echo ""

# Example 3: Get assets for a client
echo "Example 3: Get assets for a client"
echo "---------------------------------"
curl_command="curl -X GET \"${API_ENDPOINT}api/assets/client123\""
echo "$curl_command"
echo ""
echo "# Expected response:"
echo "{\"count\":3,\"assets\":[...]}"
echo ""

# Example 4: Get scan results
echo "Example 4: Get scan results for an asset"
echo "---------------------------------------"
curl_command="curl -X GET \"${API_ENDPOINT}api/results/client123-webserver1?limit=5\""
echo "$curl_command"
echo ""
echo "# Expected response:"
echo "{\"count\":5,\"results\":[...]}"
echo ""

# Example 5: Get open ports
echo "Example 5: Get open ports for an asset"
echo "-------------------------------------"
curl_command="curl -X GET \"${API_ENDPOINT}api/openports/client123-webserver1\""
echo "$curl_command"
echo ""
echo "# Expected response:"
echo "{\"assetId\":\"client123-webserver1\",\"openPorts\":[22,80,443],\"count\":3}"
echo ""

# Example 6: Run a manual hourly scan
echo "Example 6: Run a manual hourly scan"
echo "---------------------------------"
echo "aws lambda invoke \\
  --function-name nexusscan-scheduler \\
  --payload '{\"profileId\":\"hourly\",\"clientId\":\"client123\",\"forceRun\":true}' \\
  response.json"
echo ""

# Example 7: Monitor system
echo "Example 7: Monitor the system"
echo "---------------------------"
echo "./monitor.sh"
echo ""
