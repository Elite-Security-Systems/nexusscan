package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

func HandleSQSEvent(ctx context.Context, event events.SQSEvent) error {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	
	sqsClient := sqs.NewFromConfig(cfg)
	resultsQueueURL := os.Getenv("RESULTS_QUEUE_URL")
	
	for _, message := range event.Records {
		// Parse SQS message into scan request
		var request scanner.ScanRequest
		if err := json.Unmarshal([]byte(message.Body), &request); err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}
		
		log.Printf("Processing scan for IP %s (%d ports)", 
			request.IPAddress, len(request.PortsToScan))
		
		// Execute the scan
		result, err := scanner.ScanPorts(ctx, request)
		if err != nil {
			log.Printf("Error scanning IP %s: %v", request.IPAddress, err)
			continue
		}
		
		// Send result to results queue
		resultJSON, err := json.Marshal(result)
		if err != nil {
			log.Printf("Error marshaling result: %v", err)
			continue
		}
		
		_, err = sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
			QueueUrl:    &resultsQueueURL,
			MessageBody: aws.String(string(resultJSON)),
		})
		
		if err != nil {
			log.Printf("Error sending result: %v", err)
		}
		
		log.Printf("Scan complete for IP %s: found %d open ports", 
			request.IPAddress, len(result.OpenPorts))
	}
	
	return nil
}



func main() {
	lambda.Start(HandleSQSEvent)
}
