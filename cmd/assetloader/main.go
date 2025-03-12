package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/Elite-Security-Systems/nexusscan/pkg/database"
	"github.com/Elite-Security-Systems/nexusscan/pkg/models"
)

func main() {
	var csvFile string
	var clientID string
	
	flag.StringVar(&csvFile, "file", "", "CSV file with assets (format: name,ip,type)")
	flag.StringVar(&clientID, "client", "", "Client ID to associate with assets")
	flag.Parse()
	
	if csvFile == "" || clientID == "" {
		fmt.Println("Usage: assetloader -file=assets.csv -client=client123")
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
	if len(records) > 0 && strings.ToLower(records[0][0]) == "name" {
		// Skip header row
		records = records[1:]
	}
	
	// Process assets
	for i, record := range records {
		if len(record) < 3 {
			log.Printf("Skipping invalid record %d: %v", i+1, record)
			continue
		}
		
		name := strings.TrimSpace(record[0])
		ip := strings.TrimSpace(record[1])
		assetType := strings.TrimSpace(record[2])
		
		// Generate asset ID
		assetID := fmt.Sprintf("%s-%s", clientID, strings.ReplaceAll(name, " ", "-"))
		
		// Create asset
		asset := models.Asset{
			ID:        assetID,
			Name:      name,
			IPAddress: ip,
			Type:      assetType,
			ClientID:  clientID,
			CreatedAt: time.Now(),
		}
		
		// Store in DynamoDB
		if err := db.PutAsset(ctx, asset); err != nil {
			log.Printf("Error storing asset %s: %v", name, err)
		} else {
			log.Printf("Added asset: %s (%s)", name, ip)
		}
	}
	
	log.Printf("Import complete. Processed %d assets.", len(records))
}
