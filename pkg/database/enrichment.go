// pkg/database/enrichment.go

package database

import (
	"context"
	"log"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// HttpxEnrichment represents a stored enrichment result
type HttpxEnrichment struct {
	IPAddress     string          `json:"ipAddress" dynamodbav:"IPAddress"`
	Timestamp     string          `json:"timestamp" dynamodbav:"Timestamp"`
	ScanID        string          `json:"scanId" dynamodbav:"ScanID"`
	EnrichedPorts []HttpxResult   `json:"enrichedPorts" dynamodbav:"EnrichedPorts"`
	ScheduleID    string          `json:"scheduleId,omitempty" dynamodbav:"ScheduleID,omitempty"`
	ExpirationTime int64          `json:"expirationTime,omitempty" dynamodbav:"ExpirationTime,omitempty"`
}

// HttpxResult represents a single result from httpx
type HttpxResult struct {
    URL               string              `json:"url" dynamodbav:"URL"`
    StatusCode        int                 `json:"statusCode,omitempty" dynamodbav:"StatusCode,omitempty"`
    Title             string              `json:"title,omitempty" dynamodbav:"Title,omitempty"`
    Location          string              `json:"location,omitempty" dynamodbav:"Location,omitempty"`
    ServerHeader      string              `json:"server,omitempty" dynamodbav:"ServerHeader,omitempty"`
    ContentType       string              `json:"contentType,omitempty" dynamodbav:"ContentType,omitempty"`
    ContentLength     int                 `json:"contentLength,omitempty" dynamodbav:"ContentLength,omitempty"`
    Host              string              `json:"host,omitempty" dynamodbav:"Host,omitempty"`
    Path              string              `json:"path,omitempty" dynamodbav:"Path,omitempty"`
    Scheme            string              `json:"scheme,omitempty" dynamodbav:"Scheme,omitempty"`
    Port              string              `json:"port,omitempty" dynamodbav:"Port,omitempty"`
    ResponseTime      string              `json:"responseTime,omitempty" dynamodbav:"ResponseTime,omitempty"`
    Technologies      []string            `json:"technologies,omitempty" dynamodbav:"Technologies,omitempty"`
    Words             int                 `json:"words,omitempty" dynamodbav:"Words,omitempty"`
    Lines             int                 `json:"lines,omitempty" dynamodbav:"Lines,omitempty"`
    Method            string              `json:"method,omitempty" dynamodbav:"Method,omitempty"`
    Failed            bool                `json:"failed,omitempty" dynamodbav:"Failed,omitempty"`
    ResponseHeaders   map[string]string   `json:"responseHeaders,omitempty" dynamodbav:"ResponseHeaders,omitempty"`
    TLS               TLSData             `json:"tls,omitempty" dynamodbav:"TLS"`
    Chain             []string            `json:"chain,omitempty" dynamodbav:"Chain,omitempty"`
    Error             string              `json:"error,omitempty" dynamodbav:"Error,omitempty"`
    Timestamp         string              `json:"timestamp,omitempty" dynamodbav:"Timestamp,omitempty"`
    KnowledgeBase     map[string]string   `json:"knowledgeBase,omitempty" dynamodbav:"KnowledgeBase,omitempty"`
    Input             string              `json:"input,omitempty" dynamodbav:"Input,omitempty"`
}

// TLSData contains TLS certificate information
type TLSData struct {
    Version          string             `json:"tls_version,omitempty" dynamodbav:"Version"`
    Cipher           string             `json:"cipher,omitempty" dynamodbav:"Cipher"`
    Expired          bool               `json:"expired,omitempty" dynamodbav:"Expired"`
    SelfSigned       bool               `json:"self_signed,omitempty" dynamodbav:"SelfSigned"`
    Mismatched       bool               `json:"mismatched,omitempty" dynamodbav:"Mismatched"`
    NotBefore        string             `json:"not_before,omitempty" dynamodbav:"NotBefore"`
    NotAfter         string             `json:"not_after,omitempty" dynamodbav:"NotAfter"`
    SubjectDN        string             `json:"subject_dn,omitempty" dynamodbav:"SubjectDN"`
    SubjectCN        string             `json:"subject_cn,omitempty" dynamodbav:"SubjectCN"`
    SubjectOrg       []string           `json:"subject_org,omitempty" dynamodbav:"SubjectOrg"`
    SubjectAN        []string           `json:"subject_an,omitempty" dynamodbav:"SubjectAN"`
    Serial           string             `json:"serial,omitempty" dynamodbav:"Serial"`
    IssuerDN         string             `json:"issuer_dn,omitempty" dynamodbav:"IssuerDN"`
    IssuerCN         string             `json:"issuer_cn,omitempty" dynamodbav:"IssuerCN"`
    IssuerOrg        []string           `json:"issuer_org,omitempty" dynamodbav:"IssuerOrg"`
    FingerprintHash  map[string]string  `json:"fingerprint_hash,omitempty" dynamodbav:"FingerprintHash"`
    TLSConnection    string             `json:"tls_connection,omitempty" dynamodbav:"TLSConnection"`
    Host             string             `json:"host,omitempty" dynamodbav:"Host"`
    Port             string             `json:"port,omitempty" dynamodbav:"Port"`
    ProbeStatus      bool               `json:"probe_status,omitempty" dynamodbav:"ProbeStatus"`
}

// GetEnrichmentResults retrieves enrichment results for an IP
func (c *Client) GetEnrichmentResults(ctx context.Context, ipAddress string, limit int) ([]HttpxEnrichment, error) {
	if limit <= 0 {
		limit = 10 // Default limit
	}

	// Query to get enrichment results for this IP
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-enrichment"),
		KeyConditionExpression: aws.String("IPAddress = :ip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ip": &types.AttributeValueMemberS{Value: ipAddress},
		},
		ScanIndexForward: aws.Bool(false), // Sort by timestamp descending (newest first)
		Limit:            aws.Int32(int32(limit)),
	}

	result, err := c.DynamoDB.Query(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("error querying enrichment results: %v", err)
	}

	var enrichments []HttpxEnrichment
	err = attributevalue.UnmarshalListOfMaps(result.Items, &enrichments)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling enrichment results: %v", err)
	}

	return enrichments, nil
}

// GetEnrichmentResultByScan retrieves enrichment results for a specific scan
func (c *Client) GetEnrichmentResultByScan(ctx context.Context, ipAddress string, scanID string) (*HttpxEnrichment, error) {
	// Query to get enrichment results for this scan
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-enrichment"),
		KeyConditionExpression: aws.String("IPAddress = :ip"),
		FilterExpression:       aws.String("ScanID = :scanId"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ip":     &types.AttributeValueMemberS{Value: ipAddress},
			":scanId": &types.AttributeValueMemberS{Value: scanID},
		},
		Limit: aws.Int32(1), // We only need one result
	}

	result, err := c.DynamoDB.Query(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("error querying enrichment result: %v", err)
	}

	if len(result.Items) == 0 {
		return nil, fmt.Errorf("no enrichment result found for IP %s and scan ID %s", ipAddress, scanID)
	}

	var enrichment HttpxEnrichment
	err = attributevalue.UnmarshalMap(result.Items[0], &enrichment)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling enrichment result: %v", err)
	}

	return &enrichment, nil
}

// GetLatestEnrichmentResult retrieves the latest enrichment result for an IP
func (c *Client) GetLatestEnrichmentResult(ctx context.Context, ipAddress string) (*HttpxEnrichment, error) {
	// Query to get the latest enrichment result for this IP
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-enrichment"),
		KeyConditionExpression: aws.String("IPAddress = :ip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ip": &types.AttributeValueMemberS{Value: ipAddress},
		},
		ScanIndexForward: aws.Bool(false), // Sort by timestamp descending (newest first)
		Limit:            aws.Int32(1),    // Only get the most recent result
	}

	result, err := c.DynamoDB.Query(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("error querying latest enrichment result: %v", err)
	}

	if len(result.Items) == 0 {
		return nil, fmt.Errorf("no enrichment results found for IP %s", ipAddress)
	}

	var enrichment HttpxEnrichment
	err = attributevalue.UnmarshalMap(result.Items[0], &enrichment)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling enrichment result: %v", err)
	}

	return &enrichment, nil
}

// DeleteIPEnrichments deletes all enrichment results for an IP (used when deleting an IP)
func (c *Client) DeleteIPEnrichments(ctx context.Context, ipAddress string) error {
	// Query to get all enrichment results for this IP
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String("nexusscan-enrichment"),
		KeyConditionExpression: aws.String("IPAddress = :ip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ip": &types.AttributeValueMemberS{Value: ipAddress},
		},
		ProjectionExpression: aws.String("IPAddress, Timestamp"),
	}

	// Paginate through all results
	paginator := dynamodb.NewQueryPaginator(c.DynamoDB, queryInput)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Printf("Error querying enrichment results for IP %s: %v", ipAddress, err)
			return err
		}

		if len(page.Items) == 0 {
			break
		}

		// Process up to 25 items at a time (DynamoDB batch limit)
		for i := 0; i < len(page.Items); i += 25 {
			end := i + 25
			if end > len(page.Items) {
				end = len(page.Items)
			}

			batch := page.Items[i:end]

			// Create delete requests for this batch
			deleteRequests := make([]types.WriteRequest, len(batch))
			for j, item := range batch {
				deleteRequests[j] = types.WriteRequest{
					DeleteRequest: &types.DeleteRequest{
						Key: map[string]types.AttributeValue{
							"IPAddress": item["IPAddress"],
							"Timestamp": item["Timestamp"],
						},
					},
				}
			}

			// Execute batch delete
			_, err := c.DynamoDB.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
				RequestItems: map[string][]types.WriteRequest{
					"nexusscan-enrichment": deleteRequests,
				},
			})

			if err != nil {
				log.Printf("Error batch deleting enrichment results for IP %s: %v", ipAddress, err)
				return err
			}
		}
	}

	return nil
}
