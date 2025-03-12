package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

// SchedulerEvent triggers the scheduling process
type SchedulerEvent struct {
	ForceRun    bool   `json:"forceRun"`
	ProfileID   string `json:"profileId"`
	ClientID    string `json:"clientId"`
	MaxAssets   int    `json:"maxAssets"`
}

// GetPendingScans finds assets due for scanning
func GetPendingScans(ctx context.Context, db *database.Client, profileID string, maxAssets int) ([]models.Asset, error) {
	// Query DynamoDB for assets
	// This is a simplified implementation - in a real system, you would track when assets were last scanned
	// and only return those that need scanning based on the profile interval
	
	// For demonstration, we'll just get a limited set of assets
	query := &dynamodb.ScanInput{
		TableName: aws.String("nexusscan-assets"),
		Limit:     aws.Int32(int32(maxAssets)),
	}
	
	result, err := db.DynamoDB.Scan(ctx, query)
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

// ProcessPortRanges converts port range strings to actual port lists
func ProcessPortRanges(portRanges []string) ([]int, error) {
	var ports []int
	
	for _, rangeStr := range portRanges {
		// Check if it's a single port
		if !strings.Contains(rangeStr, "-") {
			port, err := strconv.Atoi(rangeStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeStr)
			}
			ports = append(ports, port)
			continue
		}
		
		// Process range
		parts := strings.Split(rangeStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range: %s", rangeStr)
		}
		
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid start port: %s", parts[0])
		}
		
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid end port: %s", parts[1])
		}
		
		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	}
	
	return ports, nil
}

// SplitIntoBatches divides ports into batches for Lambda functions
func SplitIntoBatches(ports []int, batchSize int) [][]int {
	if batchSize <= 0 {
		batchSize = 1000 // Default
	}
	
	var batches [][]int
	for i := 0; i < len(ports); i += batchSize {
		end := i + batchSize
		if end > len(ports) {
			end = len(ports)
		}
		batches = append(batches, ports[i:end])
	}
	
	return batches
}

// ScheduleScan prepares and dispatches scan tasks
func ScheduleScan(ctx context.Context, asset models.Asset, profile models.ScanProfile, sqsClient *sqs.Client, db *database.Client) error {
	// Determine ports to scan based on profile strategy
	var portsToScan []int
	
	switch profile.PortStrategy {
	case "previous_open":
		// Get previously open ports from database
		openPorts, err := db.GetOpenPorts(ctx, asset.ID)
		if err != nil {
			log.Printf("Error getting open ports for asset %s: %v", asset.ID, err)
			openPorts = []int{} // Default to empty list
		}
		
		// If no open ports found, use a small set of common ports
		if len(openPorts) == 0 {
			openPorts = []int{22, 80, 443, 3389} // Minimal set of common ports
		}
		
		portsToScan = openPorts
		
	case "top_ports":
		portsToScan = models.GetOptimizedPortList("top_ports")
		
	case "important_ports":
		portsToScan = models.GetOptimizedPortList("important_ports")
		
	case "full_range":
		// Process port ranges from profile
		if len(profile.PortRanges) > 0 {
			var err error
			portsToScan, err = ProcessPortRanges(profile.PortRanges)
			if err != nil {
				log.Printf("Error processing port ranges: %v", err)
				return err
			}
		} else {
			// Default to all ports
			portsToScan = make([]int, 65535)
			for i := 0; i < 65535; i++ {
				portsToScan[i] = i + 1
			}
		}
	}
	
	// Split ports into optimal batches for Lambda functions
	batchSize := 1000 // Default batch size
	if profile.PortStrategy == "full_range" {
		batchSize = 5000 // Larger batch size for full range scans
	}
	
	batches := SplitIntoBatches(portsToScan, batchSize)
	
	// Create scan ID
	scanID := fmt.Sprintf("scan-%s-%d", asset.ID, time.Now().Unix())
	
	// Get queue URL
	tasksQueueURL := os.Getenv("TASKS_QUEUE_URL")
	if tasksQueueURL == "" {
		log.Printf("TASKS_QUEUE_URL environment variable not set")
		return fmt.Errorf("TASKS_QUEUE_URL not set")
	}
	
	// Submit scan tasks to SQS
	for i, batch := range batches {
		request := scanner.ScanRequest{
			AssetID:      asset.ID,
			AssetIP:      asset.IPAddress,
			ClientID:     asset.ClientID,
			ScanProfile:  profile.ID,
			PortsToScan:  batch,
			BatchID:      i,
			TotalBatches: len(batches),
			ScanID:       scanID,
			TimeoutMs:    profile.TimeoutMs,
			Concurrency:  profile.Concurrency,
			RetryCount:   profile.RetryCount,
		}
		
		// Convert to JSON
		requestJSON, err := json.Marshal(request)
		if err != nil {
			log.Printf("Error marshaling request: %v", err)
			continue
		}
		
		// Send to SQS
		_, err = sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
			QueueUrl:    &tasksQueueURL,
			MessageBody: aws.String(string(requestJSON)),
		})
		
		if err != nil {
			log.Printf("Error sending task to SQS: %v", err)
			continue
		}
		
		log.Printf("Scheduled scan batch %d/%d for asset %s (%s)", 
			i+1, len(batches), asset.ID, asset.IPAddress)
	}
	
	return nil
}

func HandleSchedule(ctx context.Context, event SchedulerEvent) error {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Printf("Error loading AWS config: %v", err)
		return err
	}
	
	sqsClient := sqs.NewFromConfig(cfg)
	db := database.NewClient(cfg)
	
	// Get scan profiles
	profiles := models.GetDefaultScanProfiles()
	
	// Default max assets if not specified
	maxAssets := event.MaxAssets
	if maxAssets <= 0 {
		maxAssets = 100 // Default to 100 assets per run
	}
	
	// If specific profile requested
	if event.ProfileID != "" {
		profile, exists := profiles[event.ProfileID]
		if !exists {
			log.Printf("Unknown profile ID: %s", event.ProfileID)
			return fmt.Errorf("unknown profile ID: %s", event.ProfileID)
		}
		
		log.Printf("Running %s scan profile", profile.Name)
		
		// Get assets to scan (with optional client filter)
		var assets []models.Asset
		var err error
		
		if event.ClientID != "" {
			// Get assets for specific client
			assets, err = db.GetAssetsByClient(ctx, event.ClientID)
			if err != nil {
				log.Printf("Error getting assets for client %s: %v", event.ClientID, err)
				return err
			}
		} else {
			// Get all pending assets
			assets, err = GetPendingScans(ctx, db, event.ProfileID, maxAssets)
			if err != nil {
				log.Printf("Error getting pending scans: %v", err)
				return err
			}
		}
		
		// Limit assets if needed
		if len(assets) > maxAssets {
			assets = assets[:maxAssets]
		}
		
		log.Printf("Scheduling %d assets for scanning", len(assets))
		
		// Schedule scans for each asset
		for _, asset := range assets {
			if err := ScheduleScan(ctx, asset, profile, sqsClient, db); err != nil {
				log.Printf("Error scheduling scan for asset %s: %v", asset.ID, err)
			}
		}
		
		return nil
	}
	
	// Otherwise process all profiles
	for _, profile := range profiles {
		// Skip profiles not due for execution
		// In a real system, you would check the timestamp of when this profile was last run
		// and determine if it's time to run again based on the interval
		
		// Get assets to scan
		assets, err := GetPendingScans(ctx, db, profile.ID, maxAssets)
		if err != nil {
			log.Printf("Error getting pending scans for profile %s: %v", profile.ID, err)
			continue
		}
		
		// Limit assets if needed
		if len(assets) > maxAssets {
			assets = assets[:maxAssets]
		}
		
		log.Printf("Scheduling %d assets for %s scan", len(assets), profile.Name)
		
		// Schedule scans for each asset
		for _, asset := range assets {
			if err := ScheduleScan(ctx, asset, profile, sqsClient, db); err != nil {
				log.Printf("Error scheduling scan for asset %s: %v", asset.ID, err)
			}
		}
	}
	
	return nil
}

func main() {
	lambda.Start(HandleSchedule)
}
