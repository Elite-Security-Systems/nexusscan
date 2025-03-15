// cmd/enricher/main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// EnricherRequest defines the input for an enrichment
type EnricherRequest struct {
	IPAddress  string   `json:"ipAddress"`
	ScanID     string   `json:"scanId"`
	OpenPorts  []int    `json:"openPorts"`
	ImmediateMode bool   `json:"immediateMode"`
	ScheduleID string   `json:"scheduleId,omitempty"`
}

type HttpxResult struct {
    URL               string              `json:"url"`
    StatusCode        int                 `json:"status_code,omitempty"`
    Title             string              `json:"title,omitempty"`
    Location          string              `json:"location,omitempty"`
    ServerHeader      string              `json:"server,omitempty"`
    ContentType       string              `json:"content_type,omitempty"`
    ContentLength     int                 `json:"content_length,omitempty"`
    Host              string              `json:"host,omitempty"`
    Path              string              `json:"path,omitempty"`
    Scheme            string              `json:"scheme,omitempty"`
    Port              string              `json:"port,omitempty"`
    ResponseTime      string              `json:"time,omitempty"`
    Technologies      []string            `json:"tech,omitempty"`
    Words             int                 `json:"words,omitempty"`
    Lines             int                 `json:"lines,omitempty"`
    Method            string              `json:"method,omitempty"`
    Failed            bool                `json:"failed,omitempty"`
    TLS               TLSData             `json:"tls,omitempty" dynamodbav:"TLS"`
    Chain             []string            `json:"chain,omitempty"`
    Error             string              `json:"error,omitempty"`
    Timestamp         string              `json:"timestamp,omitempty"`
    KnowledgeBase     map[string]any      `json:"knowledgebase,omitempty"`
    Input             string              `json:"input,omitempty"`
    A                 []string            `json:"a,omitempty"`
    ResponseHeaders   map[string]string   `json:"response_headers,omitempty"`
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

// EnrichmentResult stores the final output
type EnrichmentResult struct {
    IPAddress     string        `json:"ipAddress"`
    ScanID        string        `json:"scanId"`
    EnrichedPorts []HttpxResult `json:"enrichedPorts"`
    Timestamp     string        `json:"timestamp"`
    ScheduleID    string        `json:"scheduleId,omitempty"`
}

// Table stores the enrichment results
const EnrichmentTable = "nexusscan-enrichment"

// Execute httpx on a list of ports for an IP
// Update the executeHttpx function in the enricher code
func executeHttpx(ipAddress string, ports []int) ([]HttpxResult, error) {
    // Create targets in format of http://ip:port and https://ip:port
    var targets []string
    for _, port := range ports {
        // HTTP
        targets = append(targets, fmt.Sprintf("http://%s:%d", ipAddress, port))
        // HTTPS
        targets = append(targets, fmt.Sprintf("https://%s:%d", ipAddress, port))
    }

    // Write targets to temporary file
    tempFile, err := os.CreateTemp("/tmp", "targets-*.txt")
    if err != nil {
        return nil, fmt.Errorf("error creating temp file: %v", err)
    }
    defer os.Remove(tempFile.Name())

    for _, target := range targets {
        if _, err := tempFile.WriteString(target + "\n"); err != nil {
            return nil, fmt.Errorf("error writing to temp file: %v", err)
        }
    }
    tempFile.Close()

    // Add debug logs to check the environment
    log.Printf("Temp file created at: %s", tempFile.Name())
    
    // List directories to see what's available
    log.Printf("Listing directories for debugging...")
    for _, dir := range []string{"/opt", "/var/task", "/opt/bin", "/tmp"} {
        cmd := exec.Command("ls", "-la", dir)
        output, _ := cmd.CombinedOutput()
        log.Printf("Contents of %s directory: %s", dir, string(output))
    }

    // Attempt to find httpx in multiple locations
    possiblePaths := []string{
        "/opt/bin/httpx",
        "/opt/bin/find-httpx.sh",
        "/opt/httpx",
        "httpx",
    }
    
    var httpxPath string
    for _, path := range possiblePaths {
        if _, err := os.Stat(path); err == nil {
            httpxPath = path
            log.Printf("Found httpx at: %s", httpxPath)
            break
        }
    }
    
    if httpxPath == "" {
        // Try to find httpx in PATH
        cmd := exec.Command("which", "httpx")
        output, _ := cmd.CombinedOutput()
        if strings.TrimSpace(string(output)) != "" {
            httpxPath = strings.TrimSpace(string(output))
            log.Printf("Found httpx using which: %s", httpxPath)
        } else {
            // Try to use the httpx from the layer
            httpxPath = "/opt/bin/httpx"
            log.Printf("Using default httpx path: %s", httpxPath)
        }
    }
    
    // Set up httpx command with all required arguments
    args := []string{
        "-silent",
        "-l", tempFile.Name(),
        "-j",              // JSON output
        "-sc",             // Status code
        "-title",          // Page title
        "-location",       // Redirection location
        "-server",         // Server header
        "-content-length", // Content length
        "-tls-grab",       // TLS data
        "-include-chain",  // Include certificate chain
//        "-no-fallback",    // Don't fallback to http if https fails
	"-no-fallback-scheme",
    }

    // Execute httpx command
    log.Printf("Executing: %s %s", httpxPath, strings.Join(args, " "))
    cmd := exec.Command(httpxPath, args...)
    output, err := cmd.CombinedOutput()
    log.Printf("Output from command: %s", string(output))
    
    if err != nil {
        // Try to create a copy of httpx in /tmp as a last resort
        if _, statErr := os.Stat("/opt/bin/httpx"); statErr == nil {
            log.Printf("Trying to copy httpx to /tmp as last resort")
            copyCmd := exec.Command("cp", "/opt/bin/httpx", "/tmp/httpx")
            copyCmd.Run()
            os.Chmod("/tmp/httpx", 0755)
            
            // Try executing from /tmp
            cmd = exec.Command("/tmp/httpx", args...)
            output, err = cmd.CombinedOutput()
            log.Printf("Output from /tmp/httpx command: %s", string(output))
            
            if err != nil {
                return nil, fmt.Errorf("error executing httpx (both attempts): %v, output: %s", err, string(output))
            }
        } else {
            return nil, fmt.Errorf("error executing httpx: %v, output: %s", err, string(output))
        }
    }

    // Parse JSON results
    var results []HttpxResult
    lines := strings.Split(string(output), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        var result HttpxResult
        if err := json.Unmarshal([]byte(line), &result); err != nil {
            log.Printf("Warning: Error parsing httpx result: %v", err)
            continue
        }
        results = append(results, result)
    }

    log.Printf("Httpx found %d results for IP %s", len(results), ipAddress)
    return results, nil
}


// Store enrichment results in DynamoDB
func storeEnrichmentResults(ctx context.Context, ipAddress, scanId, scheduleId string, results []HttpxResult) error {
    // Initialize AWS clients
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return fmt.Errorf("error loading AWS config: %v", err)
    }

    // Create DynamoDB client
    dynamoClient := dynamodb.NewFromConfig(cfg)

    // Prepare DynamoDB item
    timestamp := time.Now().Format(time.RFC3339)
    enrichmentResult := EnrichmentResult{
        IPAddress:     ipAddress,
        ScanID:        scanId,
        EnrichedPorts: results,
        Timestamp:     timestamp,
        ScheduleID:    scheduleId,
    }

    // Marshal the struct to DynamoDB AttributeValues
    av, err := attributevalue.MarshalMap(enrichmentResult)
    if err != nil {
        return fmt.Errorf("error marshaling result: %v", err)
    }

    // Set TTL (30 days)
    av["ExpirationTime"] = &types.AttributeValueMemberN{
        Value: strconv.FormatInt(time.Now().Add(30*24*time.Hour).Unix(), 10),
    }

    // Put item in DynamoDB
    _, err = dynamoClient.PutItem(ctx, &dynamodb.PutItemInput{
        TableName: aws.String(EnrichmentTable),
        Item:      av,
    })
    if err != nil {
        return fmt.Errorf("error storing enrichment result: %v", err)
    }

    log.Printf("Successfully stored enrichment results for IP %s with %d results", ipAddress, len(results))
    return nil
}

// Main Lambda handler
func handleRequest(ctx context.Context, request EnricherRequest) error {
	log.Printf("Received enrichment request for IP %s with %d open ports", request.IPAddress, len(request.OpenPorts))

	if len(request.OpenPorts) == 0 {
		log.Printf("No open ports to enrich for IP %s, skipping", request.IPAddress)
		return nil
	}

	// Execute httpx on open ports
	results, err := executeHttpx(request.IPAddress, request.OpenPorts)
	if err != nil {
		log.Printf("Error executing httpx: %v", err)
		return err
	}

	log.Printf("Httpx found %d results for IP %s", len(results), request.IPAddress)

	// Store results in DynamoDB
	err = storeEnrichmentResults(ctx, request.IPAddress, request.ScanID, request.ScheduleID, results)
	if err != nil {
		log.Printf("Error storing enrichment results: %v", err)
		return err
	}

	log.Printf("Enrichment completed for IP %s", request.IPAddress)
	return nil
}

func main() {
	lambda.Start(handleRequest)
}
