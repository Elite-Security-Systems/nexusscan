package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

// SchedulerEvent triggers the scheduling process
type SchedulerEvent struct {
	// For immediate scans of a single IP
	Immediate bool   `json:"immediate"`
	IP        string `json:"ip"`
	PortSet   string `json:"portSet"`
	Ports     []int  `json:"ports"`
	
	// For bulk immediate scans
	IPs []string `json:"ips"`
	
	// For scheduled scans
	ScheduleType string `json:"scheduleType"` // hourly, 12hour, daily, weekly, monthly
	MaxIPs       int    `json:"maxIPs"`
}

// SplitIntoBatches divides ports into batches for Lambda functions
func SplitIntoBatches(ports []int, batchSize int) [][]int {
	if batchSize <= 0 {
		batchSize = 4000 // Default
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
func ScheduleScan(ctx context.Context, ipAddress string, portSet string, sqsClient *sqs.Client, db *database.Client) error {
	// Determine ports to scan based on port set
	var portsToScan []int
	
	if portSet == "previous_open" {
		// Get previously open ports from database
		openPorts, err := db.GetOpenPorts(ctx, ipAddress)
		if err != nil {
			log.Printf("Error getting open ports for IP %s: %v", ipAddress, err)
			openPorts = []int{} // Default to empty list
		}
		
		// If no open ports found, use a small set of common ports
		if len(openPorts) == 0 {
			openPorts = []int{22, 80, 443, 3389} // Minimal set of common ports
		}
		
		portsToScan = openPorts
	} else {
		// Get ports based on port set name
		portsToScan = models.GetPortSet(portSet)
		if len(portsToScan) == 0 {
			return fmt.Errorf("invalid port set: %s", portSet)
		}
	}
	
	// Split ports into optimal batches for Lambda functions
	batchSize := 4000 // Default batch size
	if portSet == "full_65k" {
		batchSize = 10000 // Larger batch size for full range scans
	}
	
	batches := SplitIntoBatches(portsToScan, batchSize)
	
	// Create scan ID
	scanID := fmt.Sprintf("scan-%s-%d", ipAddress, time.Now().Unix())
	
	// Get queue URL
	tasksQueueURL := os.Getenv("TASKS_QUEUE_URL")
	if tasksQueueURL == "" {
		log.Printf("TASKS_QUEUE_URL environment variable not set")
		return fmt.Errorf("TASKS_QUEUE_URL not set")
	}
	
	// Submit scan tasks to SQS
	for i, batch := range batches {
		request := scanner.ScanRequest{
			IPAddress:    ipAddress,
			PortsToScan:  batch,
			BatchID:      i,
			TotalBatches: len(batches),
			ScanID:       scanID,
			TimeoutMs:    500, // Default timeout
			Concurrency:  50, // Default concurrency
			RetryCount:   2,   // Default retry count
		}
		
		// Convert to JSON
		requestJSON, err := json.Marshal(request)
		if err != nil {
			log.Printf("Error marshaling request: %v", err)
			continue
		}
		
		// Send to SQS
		_, err = sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
			QueueUrl:    aws.String(tasksQueueURL),
			MessageBody: aws.String(string(requestJSON)),
		})
		
		if err != nil {
			log.Printf("Error sending task to SQS: %v", err)
			continue
		}
		
		log.Printf("Scheduled scan batch %d/%d for IP %s", 
			i+1, len(batches), ipAddress)
	}
	
	return nil
}

// HandleSchedule processes scheduler events
func HandleSchedule(ctx context.Context, event SchedulerEvent) error {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Printf("Error loading AWS config: %v", err)
		return err
	}
	
	sqsClient := sqs.NewFromConfig(cfg)
	db := database.NewClient(cfg)
	
	// Handle immediate scan for a single IP
	if event.Immediate && event.IP != "" {
		log.Printf("Immediate scan requested for IP %s with port set %s", event.IP, event.PortSet)
		
		// Use provided ports if available, otherwise determine from port set
		if len(event.Ports) > 0 {
			// Create scan ID
			scanID := fmt.Sprintf("scan-%s-%d", event.IP, time.Now().Unix())
			
			// Get queue URL
			tasksQueueURL := os.Getenv("TASKS_QUEUE_URL")
			if tasksQueueURL == "" {
				return fmt.Errorf("TASKS_QUEUE_URL not set")
			}
			
			// Split ports into batches
			batches := SplitIntoBatches(event.Ports, 4000)
			
			// Submit scan tasks to SQS
			for i, batch := range batches {
				request := scanner.ScanRequest{
					IPAddress:    event.IP,
					PortsToScan:  batch,
					BatchID:      i,
					TotalBatches: len(batches),
					ScanID:       scanID,
					TimeoutMs:    500, // Default timeout
					Concurrency:  50, // Default concurrency
					RetryCount:   2,   // Default retry count
				}
				
				// Convert to JSON
				requestJSON, err := json.Marshal(request)
				if err != nil {
					log.Printf("Error marshaling request: %v", err)
					continue
				}
				
				// Send to SQS
				_, err = sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
					QueueUrl:    aws.String(tasksQueueURL),
					MessageBody: aws.String(string(requestJSON)),
				})
				
				if err != nil {
					log.Printf("Error sending task to SQS: %v", err)
					continue
				}
			}
			
			log.Printf("Immediate scan scheduled for IP %s with %d ports", 
				event.IP, len(event.Ports))
			
			return nil
		} else {
			// Schedule scan with port set
			return ScheduleScan(ctx, event.IP, event.PortSet, sqsClient, db)
		}
	}
	
	// Handle bulk immediate scan
	if event.Immediate && len(event.IPs) > 0 {
		log.Printf("Bulk immediate scan requested for %d IPs with port set %s", len(event.IPs), event.PortSet)
		
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 10) // Limit concurrent scheduling
		
		for _, ip := range event.IPs {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(ipAddress string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				if err := ScheduleScan(ctx, ipAddress, event.PortSet, sqsClient, db); err != nil {
					log.Printf("Error scheduling scan for IP %s: %v", ipAddress, err)
				}
			}(ip)
		}
		
		wg.Wait()
		log.Printf("Bulk scan scheduled for %d IPs", len(event.IPs))
		
		return nil
	}
	
	// Handle scheduled scans
	scheduleType := event.ScheduleType
	if scheduleType != "" {
		// Set default max IPs if not specified
		maxIPs := event.MaxIPs
		if maxIPs <= 0 {
			maxIPs = 100 // Default to 100 IPs per run
		}
		
		log.Printf("Running %s scheduled scans", scheduleType)
		
		// Get IPs due for scanning
		scheduledScans, err := db.GetPendingScans(ctx, scheduleType, maxIPs)
		if err != nil {
			log.Printf("Error getting pending scans: %v", err)
			return err
		}
		
		log.Printf("Found %d IPs for %s scanning", len(scheduledScans), scheduleType)
		
		// Process each scheduled scan
		for _, scheduledScan := range scheduledScans {
			if err := ScheduleScan(ctx, scheduledScan.IPAddress, scheduledScan.PortSet, sqsClient, db); err != nil {
				log.Printf("Error scheduling scan for IP %s: %v", scheduledScan.IPAddress, err)
				continue
			}
			
			// Update schedule after scan using ScheduleID
			if err := db.UpdateScheduleAfterScan(ctx, scheduledScan.ScheduleID, scheduleType); err != nil {
				log.Printf("Error updating schedule for IP %s: %v", scheduledScan.IPAddress, err)
			}
		}
		
		return nil
	}
	
	// If we get here, no valid operation was specified
	return fmt.Errorf("no valid operation specified in scheduler event")
}


func main() {
	lambda.Start(HandleSchedule)
}
