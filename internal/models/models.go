package models

import (
	"time"
)

// JobStatus represents the state of a job
type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusAssigned   JobStatus = "assigned"
	JobStatusInProgress JobStatus = "in_progress"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusRedivided  JobStatus = "redivided"
)

// Job represents a brute-force job (range of private keys to search)
type Job struct {
	ID            string    `json:"id"`
	MinHex        string    `json:"min_hex"`
	MaxHex        string    `json:"max_hex"`
	TargetAddress string    `json:"target_address"`
	Status        JobStatus `json:"status"`
	AssignedSeed  string    `json:"assigned_seed,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	AssignedAt    time.Time `json:"assigned_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	KeysChecked   int64     `json:"keys_checked"`
	LastChecksum  string    `json:"last_checksum,omitempty"` // hex of last key checked
	IsSubdivided  bool      `json:"is_subdivided"`
	ParentJobID   string    `json:"parent_job_id,omitempty"`
}

// SeedMetrics tracks performance metrics for a seed
type SeedMetrics struct {
	SeedID              string    `json:"seed_id"`
	CurrentJobID        string    `json:"current_job_id,omitempty"`
	JobsCompleted       int       `json:"jobs_completed"`
	JobsFailed          int       `json:"jobs_failed"`
	LastKeysPerSecond   float64   `json:"last_keys_per_second"`
	LastUpdateTime      time.Time `json:"last_update_time"`
	ConnectedAt         time.Time `json:"connected_at"`
	LastHeartbeat       time.Time `json:"last_heartbeat"`
	IsActive            bool      `json:"is_active"`
	AverageSendInterval int       `json:"average_send_interval"` // milliseconds
}

// JobProgress represents current progress of a job being executed
type JobProgress struct {
	JobID             string    `json:"job_id"`
	SeedID            string    `json:"seed_id"`
	KeysChecked       int64     `json:"keys_checked"`
	LastChecksum      string    `json:"last_checksum"` // hex of last key checked
	KeysPerSecond     float64   `json:"keys_per_second"`
	StartTime         time.Time `json:"start_time"`
	LastReportTime    time.Time `json:"last_report_time"`
	EstimatedTimeLeft int       `json:"estimated_time_left_seconds"`
}

// JobRequest represents a request from a seed to get a job
type JobRequest struct {
	SeedID     string `json:"seed_id"`
	NumWorkers int    `json:"num_workers"`
}

// JobResponse represents the job assigned to a seed
type JobResponse struct {
	Job   *Job   `json:"job"`
	Token string `json:"token"` // token for this specific job assignment
}

// JobStatusUpdate represents a status update from a seed about job progress
type JobStatusUpdate struct {
	JobID            string `json:"job_id"`
	SeedID           string `json:"seed_id"`
	KeysChecked      int64  `json:"keys_checked"`
	LastChecksum     string `json:"last_checksum"` // hex
	KeysPerSecond    float64 `json:"keys_per_second"`
	EstimatedTimeLeft int    `json:"estimated_time_left_seconds"`
}

// MatchAlert represents a found private key match
type MatchAlert struct {
	JobID           string    `json:"job_id"`
	SeedID          string    `json:"seed_id"`
	PrivateKey      string    `json:"private_key"` // hex
	Address         string    `json:"address"`
	TargetAddress   string    `json:"target_address"`
	FoundAt         time.Time `json:"found_at"`
	KeysCheckedUntil int64    `json:"keys_checked_until"`
}

// JobCompletion represents completion of a job
type JobCompletion struct {
	JobID            string    `json:"job_id"`
	SeedID           string    `json:"seed_id"`
	Status           JobStatus `json:"status"` // completed or failed
	KeysChecked      int64     `json:"keys_checked"`
	ErrorMessage     string    `json:"error_message,omitempty"`
	CompletedAt      time.Time `json:"completed_at"`
}
