package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
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
	s3Client := s3.NewFromConfig(cfg)
	resultsBucket := os.Getenv("RESULTS_BUCKET")
	
	for _, message := range event.Records {
		// Parse message
		var result scanner.ScanResult
		if err := json.Unmarshal([]byte(message.Body), &result); err != nil {
			log.Printf("Error parsing result: %v", err)
			continue
		}
		
		// Store scan results in DynamoDB
		if err := db.StoreScanResult(ctx, result.AssetID, result.ScanID, result.OpenPorts, 
			result.ScanDuration, result.PortsScanned); err != nil {
			log.Printf("Error storing results: %v", err)
		}
		
		// Extract open port numbers for the open ports tracker
		var openPortNumbers []int
		for _, port := range result.OpenPorts {
			openPortNumbers = append(openPortNumbers, port.Number)
		}
		
		// Update open ports tracker for hourly scans
		if len(openPortNumbers) > 0 {
			if err := db.StoreOpenPorts(ctx, result.AssetID, openPortNumbers); err != nil {
				log.Printf("Error updating open ports: %v", err)
			}
		}
		
		// Store detailed results in S3 if this is the last batch
		if result.BatchID == result.TotalBatches-1 && resultsBucket != "" {
			// Deep copy the result to avoid modifying the original
			fullResult := scanner.ScanResult{
				AssetID:      result.AssetID,
				AssetIP:      result.AssetIP,
				ScanID:       result.ScanID,
				OpenPorts:    result.OpenPorts,
				ScanDuration: result.ScanDuration,
				BatchID:      result.BatchID,
				TotalBatches: result.TotalBatches,
				PortsScanned: result.PortsScanned,
				ScanComplete: result.ScanComplete,
			}
			
			// Convert to JSON
			resultJSON, err := json.MarshalIndent(fullResult, "", "  ")
			if err != nil {
				log.Printf("Error marshaling result for S3: %v", err)
				continue
			}
			
			// Store in S3
			key := fmt.Sprintf("detailed-reports/%s/%s.json", result.AssetID, result.ScanID)
			_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:      aws.String(resultsBucket),
				Key:         aws.String(key),
				Body:        bytes.NewReader(resultJSON),
				ContentType: aws.String("application/json"),
			})
			
			if err != nil {
				log.Printf("Error storing result in S3: %v", err)
			}
		}
		
		log.Printf("Processed results for asset %s (%d open ports)", 
			result.AssetID, len(result.OpenPorts))
	}
	
	return nil
}

func main() {
	lambda.Start(HandleSQSEvent)
}
