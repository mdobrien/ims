package pkg

import (
	"context"
	"time"
)

// Module represents a data source processor
type Module interface {
	Name() string
	Schedule() Schedule
	Process(ctx context.Context) error
}

// Schedule defines when and how to run a module
type Schedule struct {
	Interval   time.Duration
	Priority   int // Higher = more important
	Timeout    time.Duration
	MaxRetries int
}
