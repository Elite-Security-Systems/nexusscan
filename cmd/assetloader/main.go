// cmd/assetloader/main.go

package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
//	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
)

func main() {
	var csvFile string
	
	flag.StringVar(&csvFile, "file", "", "CSV file with IPs (format: ip)")
	flag.Parse()
	
	if csvFile == "" {
		fmt.Println("Usage: assetloader -file=ips.csv")
		os.Exit(1)
	}
	
	// Open CSV file
	file, err := os.Open(csvFile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()
	
	// Initialize DynamoDB client
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Error loading AWS config: %v", err)
	}
	
	db := database.NewClient(cfg)
	
	// Parse CSV
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Error reading CSV: %v", err)
	}
	
	// Check if first row is header
	if len(records) > 0 && strings.ToLower(records[0][0]) == "ip" {
		// Skip header row
		records = records[1:]
	}
	
	// Process IPs
	for i, record := range records {
		if len(record) < 1 {
			log.Printf("Skipping invalid record %d: %v", i+1, record)
			continue
		}
		
		ipAddress := strings.TrimSpace(record[0])
		
		// Store IP in DynamoDB
		if err := db.AddIP(ctx, ipAddress); err != nil {
			log.Printf("Error storing IP %s: %v", ipAddress, err)
		} else {
			log.Printf("Added IP: %s", ipAddress)
		}
	}
	
	log.Printf("Import complete. Processed %d IPs.", len(records))
}
