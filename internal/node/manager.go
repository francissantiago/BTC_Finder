package node

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/francissantiago/btc_finder/internal/models"
	"github.com/francissantiago/btc_finder/internal/storage"
)

// JobManager handles job creation, assignment, and tracking
type JobManager struct {
	storage       storage.Storage
	pendingJobs   chan *models.Job
	mu            sync.RWMutex
	assignedJobs  map[string]*models.Job // jobID -> Job
	targetAddress string
}

// NewJobManager creates a new job manager
func NewJobManager(store storage.Storage, targetAddress string) *JobManager {
	return &JobManager{
		storage:       store,
		pendingJobs:   make(chan *models.Job, 100),
		assignedJobs:  make(map[string]*models.Job),
		targetAddress: targetAddress,
	}
}

// CreateJobsFromRange divides a range into N jobs
func (jm *JobManager) CreateJobsFromRange(minHex, maxHex string, numJobs int) ([]*models.Job, error) {
	minVal := new(big.Int)
	maxVal := new(big.Int)

	if _, ok := minVal.SetString(minHex, 0); !ok {
		return nil, fmt.Errorf("invalid minHex: %s", minHex)
	}

	if _, ok := maxVal.SetString(maxHex, 0); !ok {
		return nil, fmt.Errorf("invalid maxHex: %s", maxHex)
	}

	// Calculate total keys
	totalKeys := new(big.Int).Sub(maxVal, minVal)
	jobSize := new(big.Int).Div(totalKeys, big.NewInt(int64(numJobs)))

	var jobs []*models.Job
	current := new(big.Int).Set(minVal)

	for i := 0; i < numJobs; i++ {
		var jobMax *big.Int
		if i == numJobs-1 {
			// Last job gets remaining keys
			jobMax = new(big.Int).Set(maxVal)
		} else {
			jobMax = new(big.Int).Add(current, jobSize)
		}

		job := &models.Job{
			ID:            fmt.Sprintf("job_%d_%d", time.Now().UnixNano(), i),
			MinHex:        "0x" + current.Text(16),
			MaxHex:        "0x" + jobMax.Text(16),
			TargetAddress: jm.targetAddress,
			Status:        models.JobStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			IsSubdivided:  false,
		}

		if err := jm.storage.SaveJob(job); err != nil {
			return nil, fmt.Errorf("failed to save job %s: %w", job.ID, err)
		}

		jobs = append(jobs, job)
		jm.pendingJobs <- job

		// Move to next range
		current = new(big.Int).Add(jobMax, big.NewInt(1))
	}

	return jobs, nil
}

// RequestJob returns a pending job and marks it as assigned to a seed
func (jm *JobManager) RequestJob(seedID string) (*models.Job, error) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	select {
	case job := <-jm.pendingJobs:
		job.AssignedSeed = seedID
		job.Status = models.JobStatusAssigned
		job.AssignedAt = time.Now()
		job.UpdatedAt = time.Now()

		if err := jm.storage.UpdateJobAssignment(job.ID, seedID); err != nil {
			return nil, fmt.Errorf("failed to update job assignment: %w", err)
		}

		jm.assignedJobs[job.ID] = job
		return job, nil

	default:
		// No pending jobs
		return nil, fmt.Errorf("no pending jobs available")
	}
}

// UpdateJobProgress updates progress on an assigned job
func (jm *JobManager) UpdateJobProgress(jobID string, keysChecked int64, lastChecksum string) error {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	return jm.storage.UpdateJobStatus(jobID, models.JobStatusInProgress, keysChecked, lastChecksum)
}

// CompleteJob marks a job as completed
func (jm *JobManager) CompleteJob(jobID string, keysChecked int64) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	delete(jm.assignedJobs, jobID)

	return jm.storage.UpdateJobStatus(jobID, models.JobStatusCompleted, keysChecked, "")
}

// FailJob marks a job as failed
func (jm *JobManager) FailJob(jobID string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	delete(jm.assignedJobs, jobID)

	return jm.storage.UpdateJobStatus(jobID, models.JobStatusFailed, 0, "")
}

// GetAssignedJob retrieves an assigned job
func (jm *JobManager) GetAssignedJob(jobID string) (*models.Job, error) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	job, exists := jm.assignedJobs[jobID]
	if !exists {
		return jm.storage.GetJob(jobID)
	}
	return job, nil
}

// ListPendingJobs returns all pending jobs
func (jm *JobManager) ListPendingJobs() ([]*models.Job, error) {
	return jm.storage.ListJobsByStatus(models.JobStatusPending)
}

// ListAssignedJobs returns all assigned jobs
func (jm *JobManager) ListAssignedJobs() ([]*models.Job, error) {
	return jm.storage.ListJobsByStatus(models.JobStatusAssigned)
}

// ListInProgressJobs returns all in-progress jobs
func (jm *JobManager) ListInProgressJobs() ([]*models.Job, error) {
	return jm.storage.ListJobsByStatus(models.JobStatusInProgress)
}

// HasPendingJobs checks if there are pending jobs
func (jm *JobManager) HasPendingJobs() bool {
	select {
	case <-jm.pendingJobs:
		// Received a job, put it back for RequestJob to get
		jm.pendingJobs <- nil // placeholder, should not happen in practice
		return true
	default:
		return false
	}
}

// SubdividejobAndRequeue splits a slow job into smaller parts and requeues them
func (jm *JobManager) SubdivideJobAndRequeue(jobID string, numParts int) error {
	job, err := jm.storage.GetJob(jobID)
	if err != nil {
		return fmt.Errorf("failed to get job: %w", err)
	}

	minVal := new(big.Int)
	maxVal := new(big.Int)

	if _, ok := minVal.SetString(job.MinHex, 0); !ok {
		return fmt.Errorf("invalid minHex: %s", job.MinHex)
	}

	if _, ok := maxVal.SetString(job.MaxHex, 0); !ok {
		return fmt.Errorf("invalid maxHex: %s", job.MaxHex)
	}

	// Calculate size per subdivision
	totalKeys := new(big.Int).Sub(maxVal, minVal)
	subSize := new(big.Int).Div(totalKeys, big.NewInt(int64(numParts)))

	var newJobs []*models.Job
	current := new(big.Int).Set(minVal)

	for i := 0; i < numParts; i++ {
		var subMax *big.Int
		if i == numParts-1 {
			subMax = new(big.Int).Set(maxVal)
		} else {
			subMax = new(big.Int).Add(current, subSize)
		}

		subJob := &models.Job{
			ID:            fmt.Sprintf("%s_sub_%d", jobID, i),
			MinHex:        "0x" + current.Text(16),
			MaxHex:        "0x" + subMax.Text(16),
			TargetAddress: job.TargetAddress,
			Status:        models.JobStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			IsSubdivided:  true,
			ParentJobID:   jobID,
		}

		if err := jm.storage.SaveJob(subJob); err != nil {
			return fmt.Errorf("failed to save subdivided job: %w", err)
		}

		newJobs = append(newJobs, subJob)
		jm.pendingJobs <- subJob

		current = new(big.Int).Add(subMax, big.NewInt(1))
	}

	// Mark original job as redivided
	job.Status = models.JobStatusRedivided
	job.UpdatedAt = time.Now()
	return jm.storage.SaveJob(job)
}
