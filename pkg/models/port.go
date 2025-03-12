package models

import "time"

// Port represents information about a scanned port
type Port struct {
	Number  int           `json:"number"`
	State   string        `json:"state"`
	Latency time.Duration `json:"latency"`
	Service string        `json:"service,omitempty"`
}
