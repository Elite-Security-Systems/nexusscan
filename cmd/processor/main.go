// cmd/processor/main.go

package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

func HandleSQSEvent(ctx context.Context, event events.SQSEvent) error {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Printf("Error loading AWS config: %v", err)
		return err
	}
	
	db := database.NewClient(cfg)
	
	for _, message := range event.Records {
		// Parse message
		var result scanner.ScanResult
		if err := json.Unmarshal([]byte(message.Body), &result); err != nil {
			log.Printf("Error parsing result: %v", err)
			continue
		}
		
		// Store scan results in DynamoDB
		if err := db.StoreScanResult(ctx, result.IPAddress, result.ScanID, result.OpenPorts, 
			result.ScanDuration, result.PortsScanned); err != nil {
			log.Printf("Error storing results: %v", err)
		}
		
		// Extract open port numbers for the open ports tracker
		var openPortNumbers []int
		for _, port := range result.OpenPorts {
			openPortNumbers = append(openPortNumbers, port.Number)
		}
		
		// Update open ports tracker
		if len(openPortNumbers) > 0 {
			if err := db.StoreOpenPorts(ctx, result.IPAddress, openPortNumbers); err != nil {
				log.Printf("Error updating open ports: %v", err)
			}
		}
		
		// If this is the last batch, create a final summary with all open ports
		if result.BatchID == result.TotalBatches-1 {
			// Get the complete list of open ports
			completeOpenPorts, err := db.GetOpenPorts(ctx, result.IPAddress)
			if err != nil {
				log.Printf("Error getting complete open ports for IP %s: %v", result.IPAddress, err)
			} else {
				// Create a complete result with all open ports
				var fullOpenPorts []models.Port
				for _, portNum := range completeOpenPorts {
					fullOpenPorts = append(fullOpenPorts, models.Port{
						Number:  portNum,
						State:   "open",
						Latency: 1 * time.Millisecond,
					})
				}
				
				// Store a final scan summary with complete information
				log.Printf("Storing final scan summary for IP %s with %d open ports", 
					result.IPAddress, len(fullOpenPorts))
				
				if err := db.StoreFinalScanSummary(ctx, result.IPAddress, result.ScanID, fullOpenPorts, 
					result.ScanDuration, result.PortsScanned); err != nil {
					log.Printf("Error storing final scan summary: %v", err)
				} else {
					log.Printf("Successfully stored final scan summary")
				}
			}
		}
		
		log.Printf("Processed results for IP %s (%d open ports)", 
			result.IPAddress, len(result.OpenPorts))
	}
	
	return nil
}

func main() {
	lambda.Start(HandleSQSEvent)
}
