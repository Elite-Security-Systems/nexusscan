// pkg/database/client.go

package database

import (
	"context"
	"log"
	"strconv"
	"fmt"
	"time"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
	"github.com/google/uuid"
)

// Client wraps DynamoDB client with utility methods
type Client struct {
	DynamoDB *dynamodb.Client
}

// NewClient creates a new database client
func NewClient(cfg aws.Config) *Client {
	return &Client{
		DynamoDB: dynamodb.NewFromConfig(cfg),
	}
}

// DefaultClient creates a client with default config
func DefaultClient(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return NewClient(cfg), nil
}

// AddIP adds a new IP address to the database
func (c *Client) AddIP(ctx context.Context, ipAddress string) error {
	timestamp := time.Now().Format(time.RFC3339)
	
	item := map[string]types.AttributeValue{
		"IPAddress": &types.AttributeValueMemberS{Value: ipAddress},
		"CreatedAt": &types.AttributeValueMemberS{Value: timestamp},
	}
	
	_, err := c.DynamoDB.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String("nexusscan-ips"),
		Item:      item,
	})
	
	return err
}


// StoreFinalScanSummary stores a final summary of a completed scan with all discovered ports
func (c *Client) StoreFinalScanSummary(ctx context.Context, ipAddress string, scanID string, openPorts []models.Port, scanDuration time.Duration, portsScanned int) error {
    timestamp := time.Now().Format(time.RFC3339)
    
    // Debug output to see what we're trying to store
    log.Printf("Final summary for %s with %d ports: %+v", ipAddress, len(openPorts), openPorts)
    
    // Create a simplified version of open ports with just the essential fields
    simplifiedPorts := make([]map[string]interface{}, 0, len(openPorts))
    for _, port := range openPorts {
        simplifiedPorts = append(simplifiedPorts, map[string]interface{}{
            "number": port.Number,
            "state": "open",
            "latency": 1000000, // 1ms in nanoseconds
        })
    }
    
    // Marshal the simplified ports directly
    portsJSON, err := json.Marshal(simplifiedPorts)
    if err != nil {
        log.Printf("Error marshaling ports to JSON: %v", err)
        return err
    }
    
    log.Printf("Ports JSON: %s", string(portsJSON))
    
    // Create DynamoDB item
    item := map[string]types.AttributeValue{
        "IPAddress":     &types.AttributeValueMemberS{Value: ipAddress},
        "ScanTimestamp": &types.AttributeValueMemberS{Value: timestamp + "Z"},
        "ScanId":        &types.AttributeValueMemberS{Value: scanID},
        "ScanDuration":  &types.AttributeValueMemberN{Value: formatDuration(scanDuration)},
        "PortsScanned":  &types.AttributeValueMemberN{Value: formatInt(portsScanned)},
        "IsFinalSummary": &types.AttributeValueMemberBOOL{Value: true},
        "ExpirationTime": &types.AttributeValueMemberN{Value: formatInt(int(time.Now().Add(30*24*time.Hour).Unix()))},
    }
    
    // Add open ports if there are any
    if len(openPorts) > 0 {
        // Create a list of OpenPorts attributes manually
        portsList := make([]types.AttributeValue, 0, len(openPorts))
        for _, port := range openPorts {
            portMap := map[string]types.AttributeValue{
                "number": &types.AttributeValueMemberN{Value: strconv.Itoa(port.Number)},
                "state":  &types.AttributeValueMemberS{Value: "open"},
                "latency": &types.AttributeValueMemberN{Value: "1000000"},
            }
            portsList = append(portsList, &types.AttributeValueMemberM{Value: portMap})
        }
        item["OpenPorts"] = &types.AttributeValueMemberL{Value: portsList}
    } else {
        // Empty list
        item["OpenPorts"] = &types.AttributeValueMemberL{Value: []types.AttributeValue{}}
    }
    
    _, err = c.DynamoDB.PutItem(ctx, &dynamodb.PutItemInput{
        TableName: aws.String("nexusscan-results"),
        Item:      item,
    })
    
    if err != nil {
        log.Printf("Error storing final scan summary: %v", err)
    } else {
        log.Printf("Successfully stored final scan summary for %s with %d ports", ipAddress, len(openPorts))
    }
    
    return err
}


// DeleteIP removes an IP address from the database
func (c *Client) DeleteIP(ctx context.Context, ipAddress string) error {
    // Delete from IPs table
    _, err := c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
        TableName: aws.String("nexusscan-ips"),
        Key: map[string]types.AttributeValue{
            "IPAddress": &types.AttributeValueMemberS{Value: ipAddress},
        },
    })
    if err != nil {
        return err
    }
    
    // Delete all schedules for this IP
    if err := c.DeleteIPSchedules(ctx, ipAddress); err != nil {
        log.Printf("Error deleting schedules for IP %s: %v", ipAddress, err)
    }
    
    // Delete from OpenPorts table
    _, err = c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
        TableName: aws.String("nexusscan-open-ports"),
        Key: map[string]types.AttributeValue{
            "IPAddress": &types.AttributeValueMemberS{Value: ipAddress},
        },
    })
    if err != nil {
        log.Printf("Error deleting open ports for IP %s: %v", ipAddress, err)
    }
    
    // Delete all scan results for this IP
    // This requires a query + batch delete because scan results are stored with a composite key
    scanResultsQuery := &dynamodb.QueryInput{
        TableName:              aws.String("nexusscan-results"),
        KeyConditionExpression: aws.String("IPAddress = :ip"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":ip": &types.AttributeValueMemberS{Value: ipAddress},
        },
        ProjectionExpression: aws.String("IPAddress, ScanTimestamp"),
    }
    
    // Paginate through all results
    paginator := dynamodb.NewQueryPaginator(c.DynamoDB, scanResultsQuery)
    
    for paginator.HasMorePages() {
        page, err := paginator.NextPage(ctx)
        if err != nil {
            log.Printf("Error querying scan results for IP %s: %v", ipAddress, err)
            break
        }
        
        if len(page.Items) == 0 {
            break
        }
        
        // Process up to 25 items at a time (DynamoDB batch limit)
        for i := 0; i < len(page.Items); i += 25 {
            end := i + 25
            if end > len(page.Items) {
                end = len(page.Items)
            }
            
            batch := page.Items[i:end]
            
            // Create delete requests for this batch
            deleteRequests := make([]types.WriteRequest, len(batch))
            for j, item := range batch {
                deleteRequests[j] = types.WriteRequest{
                    DeleteRequest: &types.DeleteRequest{
                        Key: map[string]types.AttributeValue{
                            "IPAddress":     item["IPAddress"],
                            "ScanTimestamp": item["ScanTimestamp"],
                        },
                    },
                }
            }
            
            // Execute batch delete
            _, err := c.DynamoDB.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
                RequestItems: map[string][]types.WriteRequest{
                    "nexusscan-results": deleteRequests,
                },
            })
            
            if err != nil {
                log.Printf("Error batch deleting scan results for IP %s: %v", ipAddress, err)
            }
        }
    }
    
    return nil
}
// GetIPs retrieves all IP addresses with pagination
func (c *Client) GetIPs(ctx context.Context, limit int, offset int) ([]models.IP, error) {
	scanInput := &dynamodb.ScanInput{
		TableName: aws.String("nexusscan-ips"),
		Limit:     aws.Int32(int32(limit)),
	}
	
	// If offset is provided, we need to scan and skip results
	if offset > 0 {
		// This is a simplified approach - in a production system you'd use LastEvaluatedKey for pagination
		scanInput.Limit = aws.Int32(int32(limit + offset))
	}
	
	result, err := c.DynamoDB.Scan(ctx, scanInput)
	if err != nil {
		return nil, err
	}
	
	var ips []models.IP
	err = attributevalue.UnmarshalListOfMaps(result.Items, &ips)
	if err != nil {
		return nil, err
	}
	
	// Apply offset if necessary
	if offset > 0 && len(ips) > offset {
		ips = ips[offset:min(len(ips), offset+limit)]
	}
	
	return ips, nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AddSchedule adds or updates a scan schedule for an IP
func (c *Client) AddSchedule(ctx context.Context, ipAddress string, scheduleType string, portSet string, enabled bool) (string, error) {
    now := time.Now()
    timestamp := now.Format(time.RFC3339)
    nextRun := now.Add(getScheduleInterval(scheduleType))
    
    // Generate a unique ID for the schedule
    scheduleID := uuid.New().String()
    
    item := map[string]types.AttributeValue{
        "ScheduleID":   &types.AttributeValueMemberS{Value: scheduleID},
        "IPAddress":    &types.AttributeValueMemberS{Value: ipAddress},
        "ScheduleType": &types.AttributeValueMemberS{Value: scheduleType},
        "PortSet":      &types.AttributeValueMemberS{Value: portSet},
        "Enabled":      &types.AttributeValueMemberBOOL{Value: enabled},
        "CreatedAt":    &types.AttributeValueMemberS{Value: timestamp},
        "UpdatedAt":    &types.AttributeValueMemberS{Value: timestamp},
        "LastRun":      &types.AttributeValueMemberS{Value: ""},
        "NextRun":      &types.AttributeValueMemberS{Value: nextRun.Format(time.RFC3339)},
    }
    
    _, err := c.DynamoDB.PutItem(ctx, &dynamodb.PutItemInput{
        TableName: aws.String("nexusscan-schedules"),
        Item:      item,
    })
    
    return scheduleID, err
}

// Helper function to determine schedule interval
func getScheduleInterval(scheduleType string) time.Duration {
	switch scheduleType {
	case "hourly":
		return 1 * time.Hour
	case "12hour":
		return 12 * time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour // Default to daily
	}
}

// DeleteSchedule removes a scan schedule for an IP
func (c *Client) DeleteSchedule(ctx context.Context, scheduleID string) error {
    _, err := c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
        TableName: aws.String("nexusscan-schedules"),
        Key: map[string]types.AttributeValue{
            "ScheduleID": &types.AttributeValueMemberS{Value: scheduleID},
        },
    })
    
    return err
}

// DeleteIPSchedules deletes all schedules for an IP (used when deleting an IP)
func (c *Client) DeleteIPSchedules(ctx context.Context, ipAddress string) error {
    // Query to get all schedules for this IP
    queryInput := &dynamodb.QueryInput{
        TableName:              aws.String("nexusscan-schedules"),
        IndexName:              aws.String("IPAddressIndex"),
        KeyConditionExpression: aws.String("IPAddress = :ip"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":ip": &types.AttributeValueMemberS{Value: ipAddress},
        },
    }
    
    result, err := c.DynamoDB.Query(ctx, queryInput)
    if err != nil {
        return err
    }
    
    for _, item := range result.Items {
        scheduleID := item["ScheduleID"].(*types.AttributeValueMemberS).Value
        
        _, err := c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
            TableName: aws.String("nexusscan-schedules"),
            Key: map[string]types.AttributeValue{
                "ScheduleID": &types.AttributeValueMemberS{Value: scheduleID},
            },
        })
        if err != nil {
            log.Printf("Error deleting schedule %s for IP %s: %v", scheduleID, ipAddress, err)
        }
    }
    
    return nil
}


// UpdateScheduleStatus enables or disables a scan schedule
func (c *Client) UpdateScheduleStatus(ctx context.Context, scheduleID string, enabled bool) error {
    updateInput := &dynamodb.UpdateItemInput{
        TableName: aws.String("nexusscan-schedules"),
        Key: map[string]types.AttributeValue{
            "ScheduleID": &types.AttributeValueMemberS{Value: scheduleID},
        },
        UpdateExpression: aws.String("SET Enabled = :enabled, UpdatedAt = :updatedAt"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":enabled":   &types.AttributeValueMemberBOOL{Value: enabled},
            ":updatedAt": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
        },
    }
    
    _, err := c.DynamoDB.UpdateItem(ctx, updateInput)
    return err
}

// GetSchedulesForIP retrieves all scan schedules for an IP
func (c *Client) GetSchedulesForIP(ctx context.Context, ipAddress string) ([]models.Schedule, error) {
    queryInput := &dynamodb.QueryInput{
        TableName:              aws.String("nexusscan-schedules"),
        IndexName:              aws.String("IPAddressIndex"),
        KeyConditionExpression: aws.String("IPAddress = :ip"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":ip": &types.AttributeValueMemberS{Value: ipAddress},
        },
    }
    
    result, err := c.DynamoDB.Query(ctx, queryInput)
    if err != nil {
        return nil, err
    }
    
    // Custom unmarshaling to handle empty time fields
    var schedules []models.Schedule
    for _, item := range result.Items {
        schedule := models.Schedule{
            ScheduleID:   getString(item, "ScheduleID"),
            IPAddress:    getString(item, "IPAddress"),
            ScheduleType: getString(item, "ScheduleType"),
            PortSet:      getString(item, "PortSet"),
            Enabled:      getBool(item, "Enabled"),
        }
        
        // Handle time fields with default values if they're empty
        schedule.CreatedAt = getTime(item, "CreatedAt")
        schedule.UpdatedAt = getTime(item, "UpdatedAt")
        schedule.LastRun = getTime(item, "LastRun")
        schedule.NextRun = getTime(item, "NextRun")
        
        schedules = append(schedules, schedule)
    }
    
    return schedules, nil
}

// GetScheduleByID retrieves a schedule by its ID
func (c *Client) GetScheduleByID(ctx context.Context, scheduleID string) (*models.Schedule, error) {
    input := &dynamodb.GetItemInput{
        TableName: aws.String("nexusscan-schedules"),
        Key: map[string]types.AttributeValue{
            "ScheduleID": &types.AttributeValueMemberS{Value: scheduleID},
        },
    }
    
    result, err := c.DynamoDB.GetItem(ctx, input)
    if err != nil {
        return nil, err
    }
    
    if result.Item == nil {
        return nil, fmt.Errorf("schedule not found")
    }
    
    schedule := &models.Schedule{
        ScheduleID:   getString(result.Item, "ScheduleID"),
        IPAddress:    getString(result.Item, "IPAddress"),
        ScheduleType: getString(result.Item, "ScheduleType"),
        PortSet:      getString(result.Item, "PortSet"),
        Enabled:      getBool(result.Item, "Enabled"),
    }
    
    // Handle time fields
    schedule.CreatedAt = getTime(result.Item, "CreatedAt")
    schedule.UpdatedAt = getTime(result.Item, "UpdatedAt")
    schedule.LastRun = getTime(result.Item, "LastRun")
    schedule.NextRun = getTime(result.Item, "NextRun")
    
    return schedule, nil
}

// Helper functions for safer item extraction
func getString(item map[string]types.AttributeValue, key string) string {
    if val, ok := item[key].(*types.AttributeValueMemberS); ok {
        return val.Value
    }
    return ""
}

func getBool(item map[string]types.AttributeValue, key string) bool {
    if val, ok := item[key].(*types.AttributeValueMemberBOOL); ok {
        return val.Value
    }
    return false
}

func getTime(item map[string]types.AttributeValue, key string) time.Time {
    if val, ok := item[key].(*types.AttributeValueMemberS); ok && val.Value != "" {
        t, err := time.Parse(time.RFC3339, val.Value)
        if err == nil {
            return t
        }
    }
    return time.Time{} // Return zero time if parsing fails
}


// GetPendingScans retrieves IPs that need to be scanned for a specific schedule type
func (c *Client) GetPendingScans(ctx context.Context, scheduleType string, maxIPs int) ([]models.ScheduleScan, error) {
    now := time.Now().Format(time.RFC3339)
    
    queryInput := &dynamodb.QueryInput{
        TableName:              aws.String("nexusscan-schedules"),
        IndexName:              aws.String("ScheduleTypeIndex"),
        KeyConditionExpression: aws.String("ScheduleType = :scheduleType"),
        FilterExpression:       aws.String("Enabled = :enabled AND NextRun <= :now"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":scheduleType": &types.AttributeValueMemberS{Value: scheduleType},
            ":enabled":      &types.AttributeValueMemberBOOL{Value: true},
            ":now":          &types.AttributeValueMemberS{Value: now},
        },
        Limit: aws.Int32(int32(maxIPs)),
    }
    
    result, err := c.DynamoDB.Query(ctx, queryInput)
    if err != nil {
        return nil, err
    }
    
    var scheduledScans []models.ScheduleScan
    for _, item := range result.Items {
        scan := models.ScheduleScan{
            ScheduleID:   getString(item, "ScheduleID"),
            IPAddress:    getString(item, "IPAddress"),
            ScheduleType: getString(item, "ScheduleType"),
            PortSet:      getString(item, "PortSet"),
        }
        
        // Parse NextRun time
        nextRunStr := getString(item, "NextRun")
        if nextRunStr != "" {
            nextRun, err := time.Parse(time.RFC3339, nextRunStr)
            if err == nil {
                scan.NextRun = nextRun
            }
        }
        
        scheduledScans = append(scheduledScans, scan)
    }
    
    return scheduledScans, nil
}

// UpdateScheduleAfterScan updates the LastRun and NextRun timestamps after a scan
func (c *Client) UpdateScheduleAfterScan(ctx context.Context, scheduleID string, scheduleType string) error {
    now := time.Now()
    nextRun := now.Add(getScheduleInterval(scheduleType))
    
    updateInput := &dynamodb.UpdateItemInput{
        TableName: aws.String("nexusscan-schedules"),
        Key: map[string]types.AttributeValue{
            "ScheduleID": &types.AttributeValueMemberS{Value: scheduleID},
        },
        UpdateExpression: aws.String("SET LastRun = :lastRun, NextRun = :nextRun, UpdatedAt = :updatedAt"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":lastRun":   &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
            ":nextRun":   &types.AttributeValueMemberS{Value: nextRun.Format(time.RFC3339)},
            ":updatedAt": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
        },
    }
    
    _, err := c.DynamoDB.UpdateItem(ctx, updateInput)
    return err
}
func (c *Client) UpdateSchedule(ctx context.Context, scheduleID string, scheduleType string, portSet string, enabled bool) error {
    updateInput := &dynamodb.UpdateItemInput{
        TableName: aws.String("nexusscan-schedules"),
        Key: map[string]types.AttributeValue{
            "ScheduleID": &types.AttributeValueMemberS{Value: scheduleID},
        },
        UpdateExpression: aws.String("SET ScheduleType = :scheduleType, PortSet = :portSet, Enabled = :enabled, UpdatedAt = :updatedAt, NextRun = :nextRun"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":scheduleType": &types.AttributeValueMemberS{Value: scheduleType},
            ":portSet":      &types.AttributeValueMemberS{Value: portSet},
            ":enabled":      &types.AttributeValueMemberBOOL{Value: enabled},
            ":updatedAt":    &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
            ":nextRun":      &types.AttributeValueMemberS{Value: time.Now().Add(getScheduleInterval(scheduleType)).Format(time.RFC3339)},
        },
    }
    
    _, err := c.DynamoDB.UpdateItem(ctx, updateInput)
    return err
}

// GetOpenPorts retrieves previously discovered open ports for an IP
func (c *Client) GetOpenPorts(ctx context.Context, ipAddress string) ([]int, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("nexusscan-open-ports"),
		Key: map[string]types.AttributeValue{
			"IPAddress": &types.AttributeValueMemberS{Value: ipAddress},
		},
	}
	
	result, err := c.DynamoDB.GetItem(ctx, input)
	if err != nil {
		return nil, err
	}
	
	if result.Item == nil {
		return []int{}, nil // No open ports found
	}
	
	// Extract open ports
	var portMap struct {
		IPAddress string `dynamodbav:"IPAddress"`
		OpenPorts []int  `dynamodbav:"OpenPorts"`
	}
	
	err = attributevalue.UnmarshalMap(result.Item, &portMap)
	if err != nil {
		return nil, err
	}
	
	return portMap.OpenPorts, nil
}

// StoreOpenPorts saves open ports for an IP
func (c *Client) StoreOpenPorts(ctx context.Context, ipAddress string, openPorts []int) error {
    // First, get the existing open ports
    existingPorts, err := c.GetOpenPorts(ctx, ipAddress)
    if err != nil {
        log.Printf("Error getting existing open ports for IP %s: %v", ipAddress, err)
        // Continue with empty list if error
        existingPorts = []int{}
    }
    
    // Merge existing ports with new ones (avoiding duplicates)
    portsMap := make(map[int]bool)
    for _, port := range existingPorts {
        portsMap[port] = true
    }
    for _, port := range openPorts {
        portsMap[port] = true
    }
    
    // Convert back to slice
    mergedPorts := make([]int, 0, len(portsMap))
    for port := range portsMap {
        mergedPorts = append(mergedPorts, port)
    }

    // Update with merged ports
    item := map[string]types.AttributeValue{
        "IPAddress":   &types.AttributeValueMemberS{Value: ipAddress},
        "LastUpdated": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
    }
    
    // Marshal port list
    portsAV, err := attributevalue.Marshal(mergedPorts)
    if err != nil {
        return err
    }
    item["OpenPorts"] = portsAV
    
    _, err = c.DynamoDB.PutItem(ctx, &dynamodb.PutItemInput{
        TableName: aws.String("nexusscan-open-ports"),
        Item:      item,
    })
    
    return err
}

// StoreScanResult saves a scan result
func (c *Client) StoreScanResult(ctx context.Context, ipAddress string, scanID string, openPorts []models.Port, scanDuration time.Duration, portsScanned int) error {
    timestamp := time.Now().Format(time.RFC3339)
    
    // Clean port data - remove service names if you don't want them
    for i := range openPorts {
        openPorts[i].Service = "" // Remove service names
    }
    
    // Marshal the open ports
    portsAV, err := attributevalue.Marshal(openPorts)
    if err != nil {
        return err
    }
    
    item := map[string]types.AttributeValue{
        "IPAddress":     &types.AttributeValueMemberS{Value: ipAddress},
        "ScanTimestamp": &types.AttributeValueMemberS{Value: timestamp},
        "ScanId":        &types.AttributeValueMemberS{Value: scanID},
        "OpenPorts":     portsAV,
        "ScanDuration":  &types.AttributeValueMemberN{Value: formatDuration(scanDuration)},
        "PortsScanned":  &types.AttributeValueMemberN{Value: formatInt(portsScanned)},
        // Set TTL for automatic cleanup (30 days for most results)
        "ExpirationTime": &types.AttributeValueMemberN{Value: formatInt(int(time.Now().Add(30*24*time.Hour).Unix()))},
    }
    
    _, err = c.DynamoDB.PutItem(ctx, &dynamodb.PutItemInput{
        TableName: aws.String("nexusscan-results"),
        Item:      item,
    })
    
    if err != nil {
        log.Printf("Error storing scan result: %v", err)
    }
    
    // Also update the IP's LastScanned timestamp
    updateInput := &dynamodb.UpdateItemInput{
        TableName: aws.String("nexusscan-ips"),
        Key: map[string]types.AttributeValue{
            "IPAddress": &types.AttributeValueMemberS{Value: ipAddress},
        },
        UpdateExpression: aws.String("SET LastScanned = :lastScanned"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":lastScanned": &types.AttributeValueMemberS{Value: timestamp},
        },
    }
    
    _, err = c.DynamoDB.UpdateItem(ctx, updateInput)
    return err
}


// GetScanResults retrieves scan results for an IP with limit
func (c *Client) GetScanResults(ctx context.Context, ipAddress string, limit int) ([]models.ScanResult, error) {
    if limit <= 0 {
        limit = 10 // Default limit
    }
    
    // Query to get all scan results for this IP
    queryInput := &dynamodb.QueryInput{
        TableName:              aws.String("nexusscan-results"),
        KeyConditionExpression: aws.String("IPAddress = :ip"),
        ExpressionAttributeValues: map[string]types.AttributeValue{
            ":ip": &types.AttributeValueMemberS{Value: ipAddress},
        },
        ScanIndexForward: aws.Bool(false), // Sort by timestamp descending (newest first)
    }
    
    result, err := c.DynamoDB.Query(ctx, queryInput)
    if err != nil {
        return nil, err
    }
    
    var scanResults []models.ScanResult
    err = attributevalue.UnmarshalListOfMaps(result.Items, &scanResults)
    if err != nil {
        return nil, err
    }
    
    // Group results by scanId
    scanIdMap := make(map[string][]models.ScanResult)
    for _, result := range scanResults {
        scanIdMap[result.ScanID] = append(scanIdMap[result.ScanID], result)
    }
    
    // Prioritize final summaries and consolidate results
    var finalResults []models.ScanResult
    for _, results := range scanIdMap {
        // Look for a final summary first
        var finalSummary *models.ScanResult
        for i := range results {
            if results[i].IsFinalSummary {
                finalSummary = &results[i]
                break
            }
        }
        
        if finalSummary != nil {
            // Use the final summary if available
            finalResults = append(finalResults, *finalSummary)
        } else {
            // Otherwise, consolidate batch results
            // Use the result with the latest timestamp as the base
            var latestResult models.ScanResult
            for _, result := range results {
                if result.ScanTimestamp > latestResult.ScanTimestamp {
                    latestResult = result
                }
            }
            
            // Combine open ports from all batches
            allOpenPorts := make([]models.Port, 0)
            totalPortsScanned := 0
            for _, result := range results {
                allOpenPorts = append(allOpenPorts, result.OpenPorts...)
                totalPortsScanned += result.PortsScanned
            }
            
            // Create a map to deduplicate ports
            portMap := make(map[int]models.Port)
            for _, port := range allOpenPorts {
                portMap[port.Number] = port
            }
            
            // Convert back to slice
            uniquePorts := make([]models.Port, 0, len(portMap))
            for _, port := range portMap {
                uniquePorts = append(uniquePorts, port)
            }
            
            // Sort by port number
            for i := 0; i < len(uniquePorts); i++ {
                for j := i + 1; j < len(uniquePorts); j++ {
                    if uniquePorts[i].Number > uniquePorts[j].Number {
                        uniquePorts[i], uniquePorts[j] = uniquePorts[j], uniquePorts[i]
                    }
                }
            }
            
            // Update the latest result with consolidated information
            latestResult.OpenPorts = uniquePorts
            latestResult.PortsScanned = totalPortsScanned
            
            finalResults = append(finalResults, latestResult)
        }
    }
    
    // Sort by timestamp descending
    for i := 0; i < len(finalResults); i++ {
        for j := i + 1; j < len(finalResults); j++ {
            if finalResults[i].ScanTimestamp < finalResults[j].ScanTimestamp {
                finalResults[i], finalResults[j] = finalResults[j], finalResults[i]
            }
        }
    }
    
    // Apply limit
    if len(finalResults) > limit {
        finalResults = finalResults[:limit]
    }
    
    return finalResults, nil
}



// Helper functions
func formatDuration(d time.Duration) string {
	return formatInt(int(d.Milliseconds()))
}

func formatInt(i int) string {
	return strconv.Itoa(i)
}
