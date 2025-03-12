// pkg/database/client.go

package database

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
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
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-schedules"),
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
		scheduleType := item["ScheduleType"].(*types.AttributeValueMemberS).Value
		
		_, err := c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String("nexusscan-schedules"),
			Key: map[string]types.AttributeValue{
				"IPAddress":    &types.AttributeValueMemberS{Value: ipAddress},
				"ScheduleType": &types.AttributeValueMemberS{Value: scheduleType},
			},
		})
		if err != nil {
			log.Printf("Error deleting schedule for IP %s: %v", ipAddress, err)
		}
	}
	
	// Delete from OpenPorts table
	_, err = c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String("nexusscan-open-ports"),
		Key: map[string]types.AttributeValue{
			"IPAddress": &types.AttributeValueMemberS{Value: ipAddress},
		},
	})
	
	return err
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
func (c *Client) AddSchedule(ctx context.Context, ipAddress string, scheduleType string, portSet string, enabled bool) error {
	now := time.Now()
	timestamp := now.Format(time.RFC3339)
	nextRun := now.Add(getScheduleInterval(scheduleType))
	
	item := map[string]types.AttributeValue{
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
	
	return err
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
func (c *Client) DeleteSchedule(ctx context.Context, ipAddress string, scheduleType string) error {
	_, err := c.DynamoDB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String("nexusscan-schedules"),
		Key: map[string]types.AttributeValue{
			"IPAddress":    &types.AttributeValueMemberS{Value: ipAddress},
			"ScheduleType": &types.AttributeValueMemberS{Value: scheduleType},
		},
	})
	
	return err
}

// UpdateScheduleStatus enables or disables a scan schedule
func (c *Client) UpdateScheduleStatus(ctx context.Context, ipAddress string, scheduleType string, enabled bool) error {
	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String("nexusscan-schedules"),
		Key: map[string]types.AttributeValue{
			"IPAddress":    &types.AttributeValueMemberS{Value: ipAddress},
			"ScheduleType": &types.AttributeValueMemberS{Value: scheduleType},
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
		KeyConditionExpression: aws.String("IPAddress = :ip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ip": &types.AttributeValueMemberS{Value: ipAddress},
		},
	}
	
	result, err := c.DynamoDB.Query(ctx, queryInput)
	if err != nil {
		return nil, err
	}
	
	var schedules []models.Schedule
	err = attributevalue.UnmarshalListOfMaps(result.Items, &schedules)
	if err != nil {
		return nil, err
	}
	
	return schedules, nil
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
	err = attributevalue.UnmarshalListOfMaps(result.Items, &scheduledScans)
	if err != nil {
		return nil, err
	}
	
	return scheduledScans, nil
}

// UpdateScheduleAfterScan updates the LastRun and NextRun timestamps after a scan
func (c *Client) UpdateScheduleAfterScan(ctx context.Context, ipAddress string, scheduleType string) error {
	now := time.Now()
	nextRun := now.Add(getScheduleInterval(scheduleType))
	
	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String("nexusscan-schedules"),
		Key: map[string]types.AttributeValue{
			"IPAddress":    &types.AttributeValueMemberS{Value: ipAddress},
			"ScheduleType": &types.AttributeValueMemberS{Value: scheduleType},
		},
		UpdateExpression: aws.String("SET LastRun = :lastRun, NextRun = :nextRun"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":lastRun": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
			":nextRun": &types.AttributeValueMemberS{Value: nextRun.Format(time.RFC3339)},
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
	item := map[string]types.AttributeValue{
		"IPAddress":   &types.AttributeValueMemberS{Value: ipAddress},
		"LastUpdated": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
	}
	
	// Marshal port list
	portsAV, err := attributevalue.Marshal(openPorts)
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
	
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-results"),
		KeyConditionExpression: aws.String("IPAddress = :ip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ip": &types.AttributeValueMemberS{Value: ipAddress},
		},
		ScanIndexForward: aws.Bool(false), // Sort by timestamp descending (newest first)
		Limit:            aws.Int32(int32(limit)),
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
	
	return scanResults, nil
}

// Helper functions
func formatDuration(d time.Duration) string {
	return formatInt(int(d.Milliseconds()))
}

func formatInt(i int) string {
	return strconv.Itoa(i)
}
