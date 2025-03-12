package models

import "time"

// Asset represents a network asset to be scanned
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
