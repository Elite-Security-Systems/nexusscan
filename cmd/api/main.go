package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
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

// Start a scan via API
func startScan(ctx context.Context, clientID, assetID, profileID string) (Response, error) {
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
	
	// Create scheduler event
	event := struct {
		ForceRun  bool   `json:"forceRun"`
		ProfileID string `json:"profileId"`
		ClientID  string `json:"clientId"`
		AssetID   string `json:"assetId,omitempty"`
	}{
		ForceRun:  true,
		ProfileID: profileID,
		ClientID:  clientID,
	}
	
	if assetID != "" {
		event.AssetID = assetID
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
		Message  string `json:"message"`
		ClientID string `json:"clientId"`
		ProfileID string `json:"profileId"`
	}{
		Message:   "Scan scheduled successfully",
		ClientID:  clientID,
		ProfileID: profileID,
	}
	
	responseJSON, _ := json.Marshal(response)
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// Get assets for a client
func getAssets(ctx context.Context, clientID string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Get assets
	assets, err := db.GetAssetsByClient(ctx, clientID)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error getting assets: %v", err))
	}
	
	// Create response
	responseJSON, _ := json.Marshal(struct {
		Count  int           `json:"count"`
		Assets []models.Asset `json:"assets"`
	}{
		Count:  len(assets),
		Assets: assets,
	})
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// Get scan results for an asset
func getScanResults(ctx context.Context, assetID string, limit int) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create DynamoDB client
	dynamoClient := dynamodb.NewFromConfig(cfg)
	
	// Set default limit if not specified
	if limit <= 0 {
		limit = 10
	}
	
	// Query DynamoDB
	input := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-results"),
		KeyConditionExpression: aws.String("AssetId = :assetId"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":assetId": &types.AttributeValueMemberS{Value: assetID},
		},
		ScanIndexForward: aws.Bool(false), // Sort by timestamp descending (newest first)
		Limit:            aws.Int32(int32(limit)),
	}
	
	result, err := dynamoClient.Query(ctx, input)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error querying results: %v", err))
	}
	
	// Parse results
	var scanResults []map[string]interface{}
	err = attributevalue.UnmarshalListOfMaps(result.Items, &scanResults)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error parsing results: %v", err))
	}
	
	// Create response
	responseJSON, _ := json.Marshal(struct {
		Count   int                      `json:"count"`
		Results []map[string]interface{} `json:"results"`
	}{
		Count:   len(scanResults),
		Results: scanResults,
	})
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
}

// Get open ports for an asset
func getOpenPorts(ctx context.Context, assetID string) (Response, error) {
	// Initialize AWS clients
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error loading AWS config: %v", err))
	}
	
	// Create database client
	db := database.NewClient(cfg)
	
	// Get open ports
	openPorts, err := db.GetOpenPorts(ctx, assetID)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Sprintf("Error getting open ports: %v", err))
	}
	
	// Create response
	responseJSON, _ := json.Marshal(struct {
		AssetID   string `json:"assetId"`
		OpenPorts []int  `json:"openPorts"`
		Count     int    `json:"count"`
	}{
		AssetID:   assetID,
		OpenPorts: openPorts,
		Count:     len(openPorts),
	})
	
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(responseJSON),
	}, nil
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
		case "scan":
			// POST /api/scan
			if request.HTTPMethod == "POST" {
				// Parse request body
				var scanRequest struct {
					ClientID  string `json:"clientId"`
					AssetID   string `json:"assetId,omitempty"`
					ProfileID string `json:"profileId"`
				}
				
				if err := json.Unmarshal([]byte(request.Body), &scanRequest); err != nil {
					response, _ := errorResponse(http.StatusBadRequest, "Invalid request body")
					return events.APIGatewayProxyResponse(response), nil
				}
				
				// Validate required fields
				if scanRequest.ClientID == "" {
					response, _ := errorResponse(http.StatusBadRequest, "ClientID is required")
					return events.APIGatewayProxyResponse(response), nil
				}
				
				if scanRequest.ProfileID == "" {
					response, _ := errorResponse(http.StatusBadRequest, "ProfileID is required")
					return events.APIGatewayProxyResponse(response), nil
				}
				
				// Start scan
				response, err := startScan(ctx, scanRequest.ClientID, scanRequest.AssetID, scanRequest.ProfileID)
				if err != nil {
					return events.APIGatewayProxyResponse(response), nil
				}
				
				return events.APIGatewayProxyResponse(response), nil
			}
			
		case "assets":
			// GET /api/assets/{clientId}
			if request.HTTPMethod == "GET" && len(pathParts) >= 3 {
				clientID := pathParts[2]
				response, err := getAssets(ctx, clientID)
				if err != nil {
					return events.APIGatewayProxyResponse(response), nil
				}
				
				return events.APIGatewayProxyResponse(response), nil
			}
			
		case "results":
			// GET /api/results/{assetId}
			if request.HTTPMethod == "GET" && len(pathParts) >= 3 {
				assetID := pathParts[2]
				
				// Parse limit query parameter
				limit := 10 // Default
				if limitStr, ok := request.QueryStringParameters["limit"]; ok {
					if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
						limit = parsedLimit
					}
				}
				
				response, err := getScanResults(ctx, assetID, limit)
				if err != nil {
					return events.APIGatewayProxyResponse(response), nil
				}
				
				return events.APIGatewayProxyResponse(response), nil
			}
			
		case "openports":
			// GET /api/openports/{assetId}
			if request.HTTPMethod == "GET" && len(pathParts) >= 3 {
				assetID := pathParts[2]
				response, err := getOpenPorts(ctx, assetID)
				if err != nil {
					return events.APIGatewayProxyResponse(response), nil
				}
				
				return events.APIGatewayProxyResponse(response), nil
			}
		}
	}
	
	// If we get here, route not found
	response, _ := errorResponse(http.StatusNotFound, "Not found")
	return events.APIGatewayProxyResponse(response), nil
}

func main() {
	lambda.Start(HandleRequest)
}
