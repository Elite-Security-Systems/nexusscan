package database

import (
	"context"
	"log"
	"time"
	"strconv"

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

// GetAsset retrieves an asset by ID
func (c *Client) GetAsset(ctx context.Context, assetID string) (*models.Asset, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("nexusscan-assets"),
		Key: map[string]types.AttributeValue{
			"AssetId": &types.AttributeValueMemberS{Value: assetID},
		},
	}

	result, err := c.DynamoDB.GetItem(ctx, input)
	if err != nil {
		return nil, err
	}
	
	if result.Item == nil {
		return nil, nil // Asset not found
	}
	
	var asset models.Asset
	err = attributevalue.UnmarshalMap(result.Item, &asset)
	if err != nil {
		return nil, err
	}
	
	return &asset, nil
}

// GetAssetsByClient retrieves all assets for a client
func (c *Client) GetAssetsByClient(ctx context.Context, clientID string) ([]models.Asset, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-assets"),
		IndexName:              aws.String("ClientIndex"),
		KeyConditionExpression: aws.String("ClientId = :clientId"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":clientId": &types.AttributeValueMemberS{Value: clientID},
		},
	}
	
	result, err := c.DynamoDB.Query(ctx, input)
	if err != nil {
		return nil, err
	}
	
	var assets []models.Asset
	err = attributevalue.UnmarshalListOfMaps(result.Items, &assets)
	if err != nil {
		return nil, err
	}
	
	return assets, nil
}

// PutAsset stores an asset in DynamoDB
func (c *Client) PutAsset(ctx context.Context, asset models.Asset) error {
	// Ensure created time is set
	if asset.CreatedAt.IsZero() {
		asset.CreatedAt = time.Now()
	}
	
	item, err := attributevalue.MarshalMap(asset)
	if err != nil {
		return err
	}
	
	_, err = c.DynamoDB.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String("nexusscan-assets"),
		Item:      item,
	})
	
	return err
}

// GetOpenPorts retrieves previously discovered open ports for an asset
func (c *Client) GetOpenPorts(ctx context.Context, assetID string) ([]int, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("nexusscan-open-ports"),
		Key: map[string]types.AttributeValue{
			"AssetId": &types.AttributeValueMemberS{Value: assetID},
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
		AssetID   string `dynamodbav:"AssetId"`
		OpenPorts []int  `dynamodbav:"OpenPorts"`
	}
	
	err = attributevalue.UnmarshalMap(result.Item, &portMap)
	if err != nil {
		return nil, err
	}
	
	return portMap.OpenPorts, nil
}

// StoreOpenPorts saves open ports for an asset
func (c *Client) StoreOpenPorts(ctx context.Context, assetID string, openPorts []int) error {
	item := map[string]types.AttributeValue{
		"AssetId": &types.AttributeValueMemberS{Value: assetID},
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
func (c *Client) StoreScanResult(ctx context.Context, assetID string, scanID string, openPorts []models.Port, scanDuration time.Duration, portsScanned int) error {
	timestamp := time.Now().Format(time.RFC3339)
	
	// Marshal the open ports
	portsAV, err := attributevalue.Marshal(openPorts)
	if err != nil {
		return err
	}
	
	item := map[string]types.AttributeValue{
		"AssetId":       &types.AttributeValueMemberS{Value: assetID},
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
	
	return err
}

// Helper functions
func formatDuration(d time.Duration) string {
	return formatInt(int(d.Milliseconds()))
}

func formatInt(i int) string {
    return strconv.Itoa(i)
}
