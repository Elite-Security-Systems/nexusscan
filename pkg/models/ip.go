// pkg/models/ip.go

package models

import "time"

// IP represents a network IP address to be scanned
type IP struct {
	IPAddress   string    `json:"ipAddress" dynamodbav:"IPAddress"`
	CreatedAt   time.Time `json:"createdAt" dynamodbav:"CreatedAt"`
	LastScanned time.Time `json:"lastScanned,omitempty" dynamodbav:"LastScanned,omitempty"`
}

// Schedule represents a scan schedule for an IP address
type Schedule struct {
    ScheduleID    string    `json:"scheduleId" dynamodbav:"ScheduleID"`     // New primary key
    IPAddress     string    `json:"ipAddress" dynamodbav:"IPAddress"`
    ScheduleType  string    `json:"scheduleType" dynamodbav:"ScheduleType"` // hourly, 12hour, daily, weekly, monthly
    PortSet       string    `json:"portSet" dynamodbav:"PortSet"`           // previous_open, top_100, custom_3500, full_65k
    Enabled       bool      `json:"enabled" dynamodbav:"Enabled"`
    CreatedAt     time.Time `json:"createdAt" dynamodbav:"CreatedAt"`
    UpdatedAt     time.Time `json:"updatedAt" dynamodbav:"UpdatedAt"`
    LastRun       time.Time `json:"lastRun,omitempty" dynamodbav:"LastRun,omitempty"`
    NextRun       time.Time `json:"nextRun" dynamodbav:"NextRun"`
}
// ScheduleScan represents a pending scan from a schedule
type ScheduleScan struct {
    ScheduleID    string    `json:"scheduleId" dynamodbav:"ScheduleID"`    // Add this field
    IPAddress     string    `json:"ipAddress" dynamodbav:"IPAddress"`
    ScheduleType  string    `json:"scheduleType" dynamodbav:"ScheduleType"`
    PortSet       string    `json:"portSet" dynamodbav:"PortSet"`
    NextRun       time.Time `json:"nextRun" dynamodbav:"NextRun"`
}

// ScanResult represents the results of a completed scan
type ScanResult struct {
    IPAddress     string    `json:"ipAddress" dynamodbav:"IPAddress"`
    ScanTimestamp string    `json:"scanTimestamp" dynamodbav:"ScanTimestamp"`
    ScanID        string    `json:"scanId" dynamodbav:"ScanId"`
    OpenPorts     []Port    `json:"openPorts" dynamodbav:"OpenPorts"`
    ScanDuration  int       `json:"scanDuration" dynamodbav:"ScanDuration"`
    PortsScanned  int       `json:"portsScanned" dynamodbav:"PortsScanned"`
    ScheduleType  string    `json:"scheduleType,omitempty" dynamodbav:"ScheduleType,omitempty"`
    ExpirationTime int64    `json:"expirationTime,omitempty" dynamodbav:"ExpirationTime,omitempty"`
    IsFinalSummary bool     `json:"isFinalSummary,omitempty" dynamodbav:"IsFinalSummary,omitempty"`
}
