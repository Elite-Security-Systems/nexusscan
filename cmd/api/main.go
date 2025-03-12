// cmd/api/main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"os"
//	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	lambdaService "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
//	"github.com/Elite-Security-Systems/nexusscan/pkg/scanner"
)

// Response represents an API response
type Response struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Helper function to create error responses
func errorResponse(statusCode int, message string) (Response, error) {
	errorJSON, _ := json.Marshal(ErrorResponse{Error: message})
	
	return Response{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(errorJSON),
	}, nil
}

// IP Management Endpoints

// addIP adds a single IP address
func addIP(ctx context.Context, ipAddress string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Add IP to database
	if err := db.AddIP(ctx, ipAddress); err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error adding IP: %v", err))
	}
	
	// Create success response
	response := struct {
		Message string `json:"message"`
		IP      string `json:"ip"`
	}{
		Message: "IP added successfully",
		IP:      ipAddress,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// addIPs adds multiple IP addresses
func addIPs(ctx context.Context, ips []string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Add each IP to database
	var addedIPs []string
	var failedIPs []string
	
	for _, ip := range ips {
		if err := db.AddIP(ctx, ip); err != nil {
			log.Printf("Error adding IP %s: %v", ip, err)
			failedIPs = append(failedIPs, ip)
		} else {
			addedIPs = append(addedIPs, ip)
		}
	}
	
	// Create response
	response := struct {
		Message   string   `json:"message"`
		AddedIPs  []string `json:"addedIPs"`
		FailedIPs []string `json:"failedIPs,omitempty"`
		Total     int      `json:"total"`
	}{
		Message:   fmt.Sprintf("Added %d out of %d IPs", len(addedIPs), len(ips)),
		AddedIPs:  addedIPs,
		FailedIPs: failedIPs,
		Total:     len(addedIPs),
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// deleteIP removes an IP address
func deleteIP(ctx context.Context, ipAddress string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Delete IP from database
	if err := db.DeleteIP(ctx, ipAddress); err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error deleting IP: %v", err))
	}
	
	// Create success response
	response := struct {
		Message string `json:"message"`
		IP      string `json:"ip"`
	}{
		Message: "IP deleted successfully",
		IP:      ipAddress,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// getIPs retrieves all IPs with pagination
func getIPs(ctx context.Context, limit int, offset int) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Get IPs from database
	ips, err := db.GetIPs(ctx, limit, offset)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error getting IPs: %v", err))
	}
	
	// Create response
	response := struct {
		IPs   []models.IP `json:"ips"`
		Count int         `json:"count"`
	}{
		IPs:   ips,
		Count: len(ips),
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// Schedule Management Endpoints

// addSchedule adds a scan schedule for an IP
func addSchedule(ctx context.Context, ipAddress string, scheduleType string, portSet string, enabled bool) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Validate schedule type
	switch scheduleType {
	case "hourly", "12hour", "daily", "weekly", "monthly":
		// Valid schedule type
	default:
		return errorResponse(http.StatusBadRequest, "Invalid schedule type. Must be one of: hourly, 12hour, daily, weekly, monthly")
	}
	
	// Validate port set
	switch portSet {
	case "previous_open", "top_100", "custom_3500", "full_65k":
		// Valid port set
	default:
		return errorResponse(http.StatusBadRequest, "Invalid port set. Must be one of: previous_open, top_100, custom_3500, full_65k")
	}
	
	// Add schedule to database
	if err := db.AddSchedule(ctx, ipAddress, scheduleType, portSet, enabled); err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error adding schedule: %v", err))
	}
	
	// Create success response
	response := struct {
		Message      string `json:"message"`
		IP           string `json:"ip"`
		ScheduleType string `json:"scheduleType"`
		PortSet      string `json:"portSet"`
		Enabled      bool   `json:"enabled"`
	}{
		Message:      "Schedule added successfully",
		IP:           ipAddress,
		ScheduleType: scheduleType,
		PortSet:      portSet,
		Enabled:      enabled,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// addSchedules adds scan schedules for multiple IPs
func addSchedules(ctx context.Context, ips []string, scheduleType string, portSet string, enabled bool) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Validate schedule type
	switch scheduleType {
	case "hourly", "12hour", "daily", "weekly", "monthly":
		// Valid schedule type
	default:
		return errorResponse(http.StatusBadRequest, "Invalid schedule type. Must be one of: hourly, 12hour, daily, weekly, monthly")
	}
	
	// Validate port set
	switch portSet {
	case "previous_open", "top_100", "custom_3500", "full_65k":
		// Valid port set
	default:
		return errorResponse(http.StatusBadRequest, "Invalid port set. Must be one of: previous_open, top_100, custom_3500, full_65k")
	}
	
	// Add schedule for each IP
	var addedIPs []string
	var failedIPs []string
	
	for _, ip := range ips {
		if err := db.AddSchedule(ctx, ip, scheduleType, portSet, enabled); err != nil {
			log.Printf("Error adding schedule for IP %s: %v", ip, err)
			failedIPs = append(failedIPs, ip)
		} else {
			addedIPs = append(addedIPs, ip)
		}
	}
	
	// Create response
	response := struct {
		Message      string   `json:"message"`
		AddedIPs     []string `json:"addedIPs"`
		FailedIPs    []string `json:"failedIPs,omitempty"`
		Total        int      `json:"total"`
		ScheduleType string   `json:"scheduleType"`
		PortSet      string   `json:"portSet"`
		Enabled      bool     `json:"enabled"`
	}{
		Message:      fmt.Sprintf("Added schedule for %d out of %d IPs", len(addedIPs), len(ips)),
		AddedIPs:     addedIPs,
		FailedIPs:    failedIPs,
		Total:        len(addedIPs),
		ScheduleType: scheduleType,
		PortSet:      portSet,
		Enabled:      enabled,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// getSchedules retrieves all schedules for an IP
func getSchedules(ctx context.Context, ipAddress string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Get schedules from database
	schedules, err := db.GetSchedulesForIP(ctx, ipAddress)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error getting schedules: %v", err))
	}
	
	// Create response
	response := struct {
		IP        string            `json:"ip"`
		Schedules []models.Schedule `json:"schedules"`
		Count     int               `json:"count"`
	}{
		IP:        ipAddress,
		Schedules: schedules,
		Count:     len(schedules),
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// updateScheduleStatus enables or disables a schedule
func updateScheduleStatus(ctx context.Context, ipAddress string, scheduleType string, enabled bool) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Update schedule status
	if err := db.UpdateScheduleStatus(ctx, ipAddress, scheduleType, enabled); err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error updating schedule status: %v", err))
	}
	
	// Create success response
	response := struct {
		Message      string `json:"message"`
		IP           string `json:"ip"`
		ScheduleType string `json:"scheduleType"`
		Enabled      bool   `json:"enabled"`
	}{
		Message:      fmt.Sprintf("Schedule %s", func() string {
		    if enabled {
		        return "enabled"
		    }
		    return "disabled"
		}()),
		IP:           ipAddress,
		ScheduleType: scheduleType,
		Enabled:      enabled,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// deleteSchedule removes a schedule
func deleteSchedule(ctx context.Context, ipAddress string, scheduleType string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Delete schedule
	if err := db.DeleteSchedule(ctx, ipAddress, scheduleType); err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error deleting schedule: %v", err))
	}
	
	// Create success response
	response := struct {
		Message      string `json:"message"`
		IP           string `json:"ip"`
		ScheduleType string `json:"scheduleType"`
	}{
		Message:      "Schedule deleted successfully",
		IP:           ipAddress,
		ScheduleType: scheduleType,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// Scan Management Endpoints

// startScan initiates a scan for an IP
func startScan(ctx context.Context, ipAddress string, portSet string, immediate bool) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Get scheduler function name
	schedulerFunction := os.Getenv("SCHEDULER_FUNCTION")
	if schedulerFunction == "" {
		return errorResponse(http.StatusInternalServerError, "SCHEDULER_FUNCTION not set")
	}
	
	// Create Lambda client
	lambdaClient := lambdaService.NewFromConfig(cfg)
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Determine ports to scan
	var portsToScan []int
	
	if portSet == "previous_open" {
		// Get previously open ports for this IP
		openPorts, err := db.GetOpenPorts(ctx, ipAddress)
		if err != nil {
			log.Printf("Error getting open ports for %s: %v", ipAddress, err)
			// Default to a small set of ports if error
			portsToScan = []int{22, 80, 443, 3389}
		} else if len(openPorts) == 0 {
			// If no open ports found, use default common ports
			portsToScan = []int{22, 80, 443, 3389}
		} else {
			portsToScan = openPorts
		}
	} else {
		// Get ports based on port set name
		portsToScan = models.GetPortSet(portSet)
		if len(portsToScan) == 0 {
			return errorResponse(http.StatusBadRequest, "Invalid port set. Must be one of: previous_open, top_100, custom_3500, full_65k")
		}
	}
	
	// Create scheduler event
	event := struct {
		Immediate bool     `json:"immediate"`
		IP        string   `json:"ip"`
		PortSet   string   `json:"portSet"`
		Ports     []int    `json:"ports"`
	}{
		Immediate: immediate,
		IP:        ipAddress,
		PortSet:   portSet,
		Ports:     portsToScan,
	}
	
	// Convert to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error marshaling event: %v", err))
	}
	
	// Invoke Lambda function
	_, err = lambdaClient.Invoke(ctx, &lambdaService.InvokeInput{
		FunctionName:   aws.String(schedulerFunction),
		Payload:        payload,
		InvocationType: lambdaTypes.InvocationTypeEvent, // Asynchronous invocation
	})
	
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error invoking scheduler: %v", err))
	}
	
	// Create success response
	response := struct {
		Message   string `json:"message"`
		IP        string `json:"ip"`
		PortSet   string `json:"portSet"`
		PortCount int    `json:"portCount"`
		Immediate bool   `json:"immediate"`
	}{
		Message:   "Scan scheduled successfully",
		IP:        ipAddress,
		PortSet:   portSet,
		PortCount: len(portsToScan),
		Immediate: immediate,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// startBulkScan initiates scans for multiple IPs
func startBulkScan(ctx context.Context, ips []string, portSet string, immediate bool) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Get scheduler function name
	schedulerFunction := os.Getenv("SCHEDULER_FUNCTION")
	if schedulerFunction == "" {
		return errorResponse(http.StatusInternalServerError, "SCHEDULER_FUNCTION not set")
	}
	
	// Create Lambda client
	lambdaClient := lambdaService.NewFromConfig(cfg)
	
	// Create database client
//	db := database.NewClient(cfg)
	
	// Validate port set
	switch portSet {
	case "previous_open", "top_100", "custom_3500", "full_65k":
		// Valid port set
	default:
		return errorResponse(http.StatusBadRequest, "Invalid port set. Must be one of: previous_open, top_100, custom_3500, full_65k")
	}
	
	// Create bulk scan event
	event := struct {
		Immediate bool     `json:"immediate"`
		IPs       []string `json:"ips"`
		PortSet   string   `json:"portSet"`
	}{
		Immediate: immediate,
		IPs:       ips,
		PortSet:   portSet,
	}
	
	// Convert to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error marshaling event: %v", err))
	}
	
	// Invoke Lambda function
	_, err = lambdaClient.Invoke(ctx, &lambdaService.InvokeInput{
		FunctionName:   aws.String(schedulerFunction),
		Payload:        payload,
		InvocationType: lambdaTypes.InvocationTypeEvent, // Asynchronous invocation
	})
	
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error invoking scheduler: %v", err))
	}
	
	// Create success response
	response := struct {
		Message   string   `json:"message"`
		IPs       []string `json:"ips"`
		PortSet   string   `json:"portSet"`
		IPCount   int      `json:"ipCount"`
		Immediate bool     `json:"immediate"`
	}{
		Message:   "Bulk scan scheduled successfully",
		IPs:       ips,
		PortSet:   portSet,
		IPCount:   len(ips),
		Immediate: immediate,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// getScanResults retrieves scan results for an IP
func getScanResults(ctx context.Context, ipAddress string, limit int) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Get scan results
	results, err := db.GetScanResults(ctx, ipAddress, limit)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error getting scan results: %v", err))
	}
	
	// Create response
	response := struct {
		IP      string              `json:"ip"`
		Results []models.ScanResult `json:"results"`
		Count   int                 `json:"count"`
	}{
		IP:      ipAddress,
		Results: results,
		Count:   len(results),
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// getOpenPorts retrieves open ports for an IP
func getOpenPorts(ctx context.Context, ipAddress string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Get open ports
	openPorts, err := db.GetOpenPorts(ctx, ipAddress)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error getting open ports: %v", err))
	}
	
	// Create response
	response := struct {
		IP        string `json:"ip"`
		OpenPorts []int  `json:"openPorts"`
		Count     int    `json:"count"`
	}{
		IP:        ipAddress,
		OpenPorts: openPorts,
		Count:     len(openPorts),
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// Handler for Lambda API Gateway
func HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Log request
	log.Printf("API Request: %s %s", request.HTTPMethod, request.Path)
	
	// Parse path
	path := request.Path
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	
	// Basic routing
	if len(pathParts) >= 2 && pathParts[0] == "api" {
		switch pathParts[1] {
		// IP Management
		case "ip":
			// POST /api/ip
			if request.HTTPMethod == "POST" {
				// Parse request body
				var ipRequest struct {
					IP string `json:"ip"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &ipRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate IP address
				if ipRequest.IP == "" {
					response, _ := errorResponse(http.StatusBadRequest, "IP address is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Add IP
				response, err := addIP(ctx, ipRequest.IP)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
			// DELETE /api/ip
			if request.HTTPMethod == "DELETE" {
				// Parse request body
				var ipRequest struct {
					IP string `json:"ip"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &ipRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate IP address
				if ipRequest.IP == "" {
					response, _ := errorResponse(http.StatusBadRequest, "IP address is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Delete IP
				response, err := deleteIP(ctx, ipRequest.IP)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
		
		case "ips":
			// POST /api/ips (bulk add)
			if request.HTTPMethod == "POST" {
				// Parse request body
				var ipsRequest struct {
					IPs []string `json:"ips"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &ipsRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate IPs
				if len(ipsRequest.IPs) == 0 {
					response, _ := errorResponse(http.StatusBadRequest, "IPs list is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Add IPs
				response, err := addIPs(ctx, ipsRequest.IPs)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
			// GET /api/ips?limit=10&offset=0
			if request.HTTPMethod == "GET" {
				// Parse query parameters
				limit := 10 // Default limit
				offset := 0 // Default offset
				
				if limitStr, ok := request.QueryStringParameters["limit"]; ok {
					if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
						limit = parsedLimit
					}
				}
				
				if offsetStr, ok := request.QueryStringParameters["offset"]; ok {
					if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
						offset = parsedOffset
					}
				}
				
				// Get IPs
				response, err := getIPs(ctx, limit, offset)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
		
		// Schedule Management
		case "schedule":
			// POST /api/schedule
			if request.HTTPMethod == "POST" {
				// Parse request body
				var scheduleRequest struct {
					IP           string `json:"ip"`
					ScheduleType string `json:"scheduleType"`
					PortSet      string `json:"portSet"`
					Enabled      bool   `json:"enabled"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &scheduleRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate required fields
				if scheduleRequest.IP == "" {
					response, _ := errorResponse(http.StatusBadRequest, "IP address is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if scheduleRequest.ScheduleType == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Schedule type is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if scheduleRequest.PortSet == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Port set is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Add schedule
				response, err := addSchedule(ctx, scheduleRequest.IP, scheduleRequest.ScheduleType, scheduleRequest.PortSet, scheduleRequest.Enabled)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
			// DELETE /api/schedule
			if request.HTTPMethod == "DELETE" {
				// Parse request body
				var scheduleRequest struct {
					IP           string `json:"ip"`
					ScheduleType string `json:"scheduleType"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &scheduleRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate required fields
				if scheduleRequest.IP == "" {
					response, _ := errorResponse(http.StatusBadRequest, "IP address is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if scheduleRequest.ScheduleType == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Schedule type is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Delete schedule
				response, err := deleteSchedule(ctx, scheduleRequest.IP, scheduleRequest.ScheduleType)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
		case "schedules":
			// POST /api/schedules (bulk add)
			if request.HTTPMethod == "POST" {
				// Parse request body
				var schedulesRequest struct {
					IPs          []string `json:"ips"`
					ScheduleType string   `json:"scheduleType"`
					PortSet      string   `json:"portSet"`
					Enabled      bool     `json:"enabled"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &schedulesRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate required fields
				if len(schedulesRequest.IPs) == 0 {
					response, _ := errorResponse(http.StatusBadRequest, "IPs list is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if schedulesRequest.ScheduleType == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Schedule type is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if schedulesRequest.PortSet == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Port set is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Add schedules
				response, err := addSchedules(ctx, schedulesRequest.IPs, schedulesRequest.ScheduleType, schedulesRequest.PortSet, schedulesRequest.Enabled)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
			// GET /api/schedules/{ip}
			if request.HTTPMethod == "GET" && len(pathParts) >= 3 {
				ipAddress := pathParts[2]
				
				// Get schedules for IP
				response, err := getSchedules(ctx, ipAddress)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
		case "schedule-status":
			// PUT /api/schedule-status
			if request.HTTPMethod == "PUT" {
				// Parse request body
				var statusRequest struct {
					IP           string `json:"ip"`
					ScheduleType string `json:"scheduleType"`
					Enabled      bool   `json:"enabled"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &statusRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate required fields
				if statusRequest.IP == "" {
					response, _ := errorResponse(http.StatusBadRequest, "IP address is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if statusRequest.ScheduleType == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Schedule type is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Update schedule status
				response, err := updateScheduleStatus(ctx, statusRequest.IP, statusRequest.ScheduleType, statusRequest.Enabled)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
		// Scan Management
		case "scan":
			// POST /api/scan
			if request.HTTPMethod == "POST" {
				// Parse request body
				var scanRequest struct {
					IP        string `json:"ip"`
					PortSet   string `json:"portSet"`
					Immediate bool   `json:"immediate"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &scanRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate required fields
				if scanRequest.IP == "" {
					response, _ := errorResponse(http.StatusBadRequest, "IP address is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if scanRequest.PortSet == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Port set is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Start scan
				response, err := startScan(ctx, scanRequest.IP, scanRequest.PortSet, scanRequest.Immediate)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
		case "scans":
			// POST /api/scans (bulk scan)
			if request.HTTPMethod == "POST" {
				// Parse request body
				var scansRequest struct {
					IPs       []string `json:"ips"`
					PortSet   string   `json:"portSet"`
					Immediate bool     `json:"immediate"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &scansRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Validate required fields
				if len(scansRequest.IPs) == 0 {
					response, _ := errorResponse(http.StatusBadRequest, "IPs list is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				if scansRequest.PortSet == "" {
					response, _ := errorResponse(http.StatusBadRequest, "Port set is required")
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				// Start bulk scan
				response, err := startBulkScan(ctx, scansRequest.IPs, scansRequest.PortSet, scansRequest.Immediate)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
		case "scan-results":
			// GET /api/scan-results/{ip}?limit=5
			if request.HTTPMethod == "GET" && len(pathParts) >= 3 {
				ipAddress := pathParts[2]
				
				// Parse limit query parameter
				limit := 10 // Default
				if limitStr, ok := request.QueryStringParameters["limit"]; ok {
					if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
						limit = parsedLimit
					}
				}
				
				// Get scan results
				response, err := getScanResults(ctx, ipAddress, limit)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
			
		case "open-ports":
			// GET /api/open-ports/{ip}
			if request.HTTPMethod == "GET" && len(pathParts) >= 3 {
				ipAddress := pathParts[2]
				
				// Get open ports
				response, err := getOpenPorts(ctx, ipAddress)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: response.StatusCode,
						Headers:    response.Headers,
						Body:       response.Body,
					}, nil
				}
				
				return events.APIGatewayProxyResponse{
					StatusCode: response.StatusCode,
					Headers:    response.Headers,
					Body:       response.Body,
				}, nil
			}
		}
	}
	
	// If we get here, route not found
	response, _ := errorResponse(http.StatusNotFound, "Not found")
	return events.APIGatewayProxyResponse{
		StatusCode: response.StatusCode,
		Headers:    response.Headers,
		Body:       response.Body,
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
