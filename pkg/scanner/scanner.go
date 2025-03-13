// pkg/scanner/scanner.go

package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
)

// ScanRequest defines the input for a scan
type ScanRequest struct {
	IPAddress     string   `json:"ipAddress"`
	PortsToScan   []int    `json:"portsToScan"`
	BatchID       int      `json:"batchId"`
	TotalBatches  int      `json:"totalBatches"`
	ScanID        string   `json:"scanId"`
	TimeoutMs     int      `json:"timeoutMs"`
	Concurrency   int      `json:"concurrency"`
	RetryCount    int      `json:"retryCount"`
	ScheduleType  string   `json:"scheduleType,omitempty"` // Optional, for scheduled scans
}

// ScanResult defines the scanner output
type ScanResult struct {
	IPAddress    string        `json:"ipAddress"`
	ScanID       string        `json:"scanId"`
	OpenPorts    []models.Port `json:"openPorts"`
	ScanDuration time.Duration `json:"duration"`
	BatchID      int           `json:"batchId"`
	TotalBatches int           `json:"totalBatches"`
	PortsScanned int           `json:"portsScanned"`
	ScanComplete bool          `json:"scanComplete"`
	ScheduleType string        `json:"scheduleType,omitempty"` // Optional, for scheduled scans
}

// Initialize connection pool
var connPoolSize = 100
var connPool = sync.Pool{
	New: func() interface{} {
		dialer := &net.Dialer{
			Timeout: 500 * time.Millisecond,
			KeepAlive: -1, // Disable keep-alive
		}
		return dialer
	},
}

// ScanPort checks if a single port is open
func ScanPort(ctx context.Context, host string, port int, timeout time.Duration, retryCount int) (bool, time.Duration) {
	// Get dialer from pool
	dialerInterface := connPool.Get()
	dialer := dialerInterface.(*net.Dialer)
	dialer.Timeout = timeout
	defer connPool.Put(dialer)
	
	addr := fmt.Sprintf("%s:%d", host, port)
	
	// First attempt
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	latency := time.Since(start)
	
	if err == nil {
		conn.Close()
		return true, latency
	}
	
	// Retry logic for potential false negatives
	if retryCount > 0 {
		// Short delay between retries
		time.Sleep(5 * time.Millisecond)
		
		for i := 0; i < retryCount; i++ {
			// Check context before retry
			select {
			case <-ctx.Done():
				return false, 0
			default:
			}
			
			start = time.Now()
			conn, err = dialer.DialContext(ctx, "tcp", addr)
			retryLatency := time.Since(start)
			
			if err == nil {
				conn.Close()
				return true, retryLatency
			}
			
			// Exponential backoff
			if i < retryCount-1 {
				time.Sleep(time.Duration(20*(i+1)) * time.Millisecond)
			}
		}
	}
	
	return false, latency
}

// ScanPorts performs port scanning with optimized concurrency
func ScanPorts(ctx context.Context, request ScanRequest) (ScanResult, error) {
	startTime := time.Now()
	
	// Configure scan parameters
	timeout := time.Duration(request.TimeoutMs) * time.Millisecond
	concurrency := request.Concurrency
	if concurrency <= 0 {
		concurrency = 50 // Default concurrency
	}
	
	retryCount := request.RetryCount
	if retryCount < 0 {
		retryCount = 0
	}
	
	// Prepare result
	result := ScanResult{
		IPAddress:    request.IPAddress,
		ScanID:       request.ScanID,
		BatchID:      request.BatchID,
		TotalBatches: request.TotalBatches,
		OpenPorts:    make([]models.Port, 0),
		PortsScanned: len(request.PortsToScan),
		ScheduleType: request.ScheduleType,
	}
	
	// Use buffered channels for worker management
	portChan := make(chan int, concurrency)
	resultChan := make(chan models.Port, concurrency)
	doneChan := make(chan struct{})
	
	// Track open ports with atomic counter
	var openPortCount int32
	
	// Start result collector
	go func() {
		for port := range resultChan {
			result.OpenPorts = append(result.OpenPorts, port)
			atomic.AddInt32(&openPortCount, 1)
		}
		close(doneChan)
	}()
	
	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for port := range portChan {
				select {
				case <-ctx.Done():
					return // Context cancelled
				default:
					// Scan the port
					isOpen, latency := ScanPort(ctx, request.IPAddress, port, timeout, retryCount)
					
					if isOpen {
						// Port is open, send to result channel
						resultChan <- models.Port{
							Number:  port,
							State:   "open",
							Latency: latency,
						}
					}
				}
			}
		}()
	}
	
	// Feed ports to workers
	go func() {
		for _, port := range request.PortsToScan {
			select {
			case <-ctx.Done():
				break
			case portChan <- port:
				// Port queued successfully
			}
		}
		close(portChan)
		
		// Wait for all workers to finish
		wg.Wait()
		close(resultChan)
	}()
	
	// Wait for results collection
	<-doneChan
	
	// Sort results by port number
	sort.Slice(result.OpenPorts, func(i, j int) bool {
		return result.OpenPorts[i].Number < result.OpenPorts[j].Number
	})
	
	result.ScanDuration = time.Since(startTime)
	result.ScanComplete = true
	
	// Log summary
	log.Printf("Scan of %s completed: %d ports scanned, %d open ports found in %v",
		request.IPAddress, len(request.PortsToScan), len(result.OpenPorts), result.ScanDuration)
	
	return result, nil
}
