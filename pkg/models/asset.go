package models

import "time"

// Asset represents a network asset to be scanned
/*
type Asset struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	IPAddress   string    `json:"ipAddress"`
	Type        string    `json:"type"`
	ClientID    string    `json:"clientId"`
	Tags        []string  `json:"tags,omitempty"`
	LastScanned time.Time `json:"lastScanned,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}
*/
type Asset struct {
    ID          string    `json:"id" dynamodbav:"AssetId"`
    Name        string    `json:"name" dynamodbav:"Name"`
    IPAddress   string    `json:"ipAddress" dynamodbav:"IPAddress"`
    Type        string    `json:"type" dynamodbav:"Type"`
    ClientID    string    `json:"clientId" dynamodbav:"ClientId"`
    Tags        []string  `json:"tags,omitempty" dynamodbav:"Tags,omitempty"`
    LastScanned time.Time `json:"lastScanned,omitempty" dynamodbav:"LastScanned,omitempty"`
    CreatedAt   time.Time `json:"createdAt" dynamodbav:"CreatedAt"`
}
