// cmd/processor/main.go

package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	lambdaService "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

// EnricherRequest defines the input for the enricher function
type EnricherRequest struct {
	IPAddress     string   `json:"ipAddress"`
	ScanID        string   `json:"scanId"`
	OpenPorts     []int    `json:"openPorts"`
	ImmediateMode bool     `json:"immediateMode"`
	ScheduleID    string   `json:"scheduleId,omitempty"`
}

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
		
		// Update open ports tracker - USING TRUE TO REPLACE EXISTING PORTS
		if err := db.StoreOpenPorts(ctx, result.IPAddress, openPortNumbers, true); err != nil {
			log.Printf("Error updating open ports: %v", err)
		}
		
		// If this is the last batch, create a final summary with all open ports
		if result.BatchID == result.TotalBatches-1 {
			// Create a complete result with the ports detected in this scan
			var fullOpenPorts []models.Port
			for _, portNum := range openPortNumbers {
				fullOpenPorts = append(fullOpenPorts, models.Port{
					Number:  portNum,
					State:   "open",
					Latency: 1 * time.Millisecond,
				})
			}
			
			// Store a final scan summary with complete information
			// USING FALSE TO ONLY INCLUDE CURRENT PORTS
			log.Printf("Storing final scan summary for IP %s with %d open ports", 
				result.IPAddress, len(fullOpenPorts))
			
			if err := db.StoreFinalScanSummary(ctx, result.IPAddress, result.ScanID, fullOpenPorts, 
				result.ScanDuration, result.PortsScanned, false); err != nil {
				log.Printf("Error storing final scan summary: %v", err)
			} else {
				log.Printf("Successfully stored final scan summary")
				
				// Trigger the enricher function only when there are open ports
				if len(openPortNumbers) > 0 {
					if err := triggerEnricher(ctx, cfg, result.IPAddress, result.ScanID, openPortNumbers, 
						true, result.ScheduleType); err != nil {
						log.Printf("Error triggering enricher: %v", err)
					}
				}
			}
		}
		
		log.Printf("Processed results for IP %s (%d open ports)", 
			result.IPAddress, len(result.OpenPorts))
	}
	
	return nil
}

// Trigger the enricher Lambda function
func triggerEnricher(ctx context.Context, cfg aws.Config, ipAddress, scanID string, openPorts []int, 
	isImmediate bool, scheduleType string) error {
	
	// Get enricher function name from environment variable
	enricherFunction := os.Getenv("ENRICHER_FUNCTION")
	if enricherFunction == "" {
		enricherFunction = "nexusscan-enricher" // Default name if not set
	}
	
	// Create Lambda client
	lambdaClient := lambdaService.NewFromConfig(cfg)
	
	// Prepare the enricher request
	request := EnricherRequest{
		IPAddress:     ipAddress,
		ScanID:        scanID,
		OpenPorts:     openPorts,
		ImmediateMode: isImmediate,
	}
	
	// If this is a scheduled scan, add the schedule information
	if scheduleType != "" {
		request.ScheduleID = scheduleType
	}
	
	// Convert to JSON
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	
	// Invoke Lambda function asynchronously
	_, err = lambdaClient.Invoke(ctx, &lambdaService.InvokeInput{
		FunctionName:   aws.String(enricherFunction),
		Payload:        payload,
		InvocationType: lambdaTypes.InvocationTypeEvent, // Asynchronous invocation
	})
	
	if err != nil {
		return err
	}
	
	log.Printf("Triggered enricher for IP %s with %d open ports", ipAddress, len(openPorts))
	return nil
}

func main() {
	awslambda.Start(HandleSQSEvent)
}
