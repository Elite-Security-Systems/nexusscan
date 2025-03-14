package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

func HandleRequest(ctx context.Context, request scanner.ScanRequest) (scanner.ScanResult, error) {
	// Log request
	log.Printf("Starting scan of %s - batch %d/%d, ports: %d",
		request.IPAddress, 
		request.BatchID+1, request.TotalBatches, len(request.PortsToScan))
	
	// Execute scan
	result, err := scanner.ScanPorts(ctx, request)
	if err != nil {
		log.Printf("Error during scan: %v", err)
		return scanner.ScanResult{}, err
	}
	
	// Store results if in AWS Lambda
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		resultsQueueURL := os.Getenv("RESULTS_QUEUE_URL")
		if resultsQueueURL != "" {
			// Initialize AWS clients
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				log.Printf("Error loading AWS config: %v", err)
			} else {
				// Send result to SQS queue
				sqsClient := sqs.NewFromConfig(cfg)
				
				// Convert result to JSON
				resultJSON, err := json.Marshal(result)
				if err != nil {
					log.Printf("Error marshaling result: %v", err)
				} else {
					// Send to SQS
					_, err = sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
						QueueUrl:    aws.String(resultsQueueURL),
						MessageBody: aws.String(string(resultJSON)),
					})
					
					if err != nil {
						log.Printf("Error sending result to SQS: %v", err)
					} else {
						log.Printf("Scan results sent to queue")
					}
				}
			}
		}
	}
	
	return result, nil
}

func main() {
	lambda.Start(HandleRequest)
}
