package node

import (
	"fmt"
	"sync"
	"time"

	"github.com/francissantiago/btc_finder/internal/models"
	"github.com/francissantiago/btc_finder/internal/storage"
)

// SeedRegistry manages connected seeds and their metrics
type SeedRegistry struct {
	storage storage.Storage
	mu      sync.RWMutex
	seeds   map[string]*models.SeedMetrics
}

// NewSeedRegistry creates a new seed registry
func NewSeedRegistry(store storage.Storage) *SeedRegistry {
	return &SeedRegistry{
		storage: store,
		seeds:   make(map[string]*models.SeedMetrics),
	}
}

// RegisterSeed registers a new seed
func (sr *SeedRegistry) RegisterSeed(seedID string) (*models.SeedMetrics, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Check if already registered
	if metrics, exists := sr.seeds[seedID]; exists && metrics.IsActive {
		return metrics, nil
	}

	now := time.Now()
	metrics := &models.SeedMetrics{
		SeedID:        seedID,
		JobsCompleted: 0,
		JobsFailed:    0,
		ConnectedAt:   now,
		LastHeartbeat: now,
		IsActive:      true,
	}

	if err := sr.storage.SaveSeedMetrics(metrics); err != nil {
		return nil, fmt.Errorf("failed to save seed metrics: %w", err)
	}

	sr.seeds[seedID] = metrics
	return metrics, nil
}

// UpdateHeartbeat updates the last heartbeat for a seed
func (sr *SeedRegistry) UpdateHeartbeat(seedID string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if metrics, exists := sr.seeds[seedID]; exists {
		metrics.LastHeartbeat = time.Now()
	}

	return sr.storage.UpdateSeedHeartbeat(seedID)
}

// UpdateSeedMetrics updates performance metrics for a seed
func (sr *SeedRegistry) UpdateSeedMetrics(seedID string, jobsCompleted, jobsFailed int, keysPerSec float64) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if metrics, exists := sr.seeds[seedID]; exists {
		metrics.JobsCompleted = jobsCompleted
		metrics.JobsFailed = jobsFailed
		metrics.LastKeysPerSecond = keysPerSec
		metrics.LastUpdateTime = time.Now()
	}

	return sr.storage.UpdateSeedMetrics(seedID, jobsCompleted, jobsFailed, keysPerSec)
}

// SetCurrentJob sets the current job for a seed
func (sr *SeedRegistry) SetCurrentJob(seedID, jobID string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if metrics, exists := sr.seeds[seedID]; exists {
		metrics.CurrentJobID = jobID
	}

	return nil
}

// GetSeedMetrics retrieves metrics for a seed
func (sr *SeedRegistry) GetSeedMetrics(seedID string) (*models.SeedMetrics, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	metrics, exists := sr.seeds[seedID]
	if !exists {
		return sr.storage.GetSeedMetrics(seedID)
	}
	return metrics, nil
}

// ListActiveSeedMetrics retrieves metrics for all active seeds
func (sr *SeedRegistry) ListActiveSeedMetrics() ([]*models.SeedMetrics, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	var allMetrics []*models.SeedMetrics
	for _, metrics := range sr.seeds {
		if metrics.IsActive {
			allMetrics = append(allMetrics, metrics)
		}
	}

	return allMetrics, nil
}

// MarkOffline marks a seed as offline
func (sr *SeedRegistry) MarkOffline(seedID string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if metrics, exists := sr.seeds[seedID]; exists {
		metrics.IsActive = false
	}

	return nil
}

// GetSlowSeedWithActiveJob returns a seed that is slower than the median and has an active job
func (sr *SeedRegistry) GetSlowSeedWithActiveJob() (*models.SeedMetrics, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	activeSeedsMetrics := make([]*models.SeedMetrics, 0)

	// Collect active seeds with current jobs
	for _, metrics := range sr.seeds {
		if metrics.IsActive && metrics.CurrentJobID != "" {
			activeSeedsMetrics = append(activeSeedsMetrics, metrics)
		}
	}

	if len(activeSeedsMetrics) == 0 {
		return nil, fmt.Errorf("no active seeds with jobs")
	}

	// Calculate median speed
	var totalSpeed float64
	for _, m := range activeSeedsMetrics {
		totalSpeed += m.LastKeysPerSecond
	}
	medianSpeed := totalSpeed / float64(len(activeSeedsMetrics))

	// Find slowest seed (if only one seed, return it if it's been working for a while)
	var slowestSeed *models.SeedMetrics
	minSpeed := medianSpeed

	for _, m := range activeSeedsMetrics {
		if m.LastKeysPerSecond < minSpeed && m.LastKeysPerSecond > 0 {
			minSpeed = m.LastKeysPerSecond
			slowestSeed = m
		}
	}

	// Only return if clearly slower than median
	if slowestSeed != nil && slowestSeed.LastKeysPerSecond < (medianSpeed * 0.5) {
		return slowestSeed, nil
	}

	return nil, fmt.Errorf("no slow seed found")
}

// CountActiveSeedsWithoutJob counts active seeds not executing any job
func (sr *SeedRegistry) CountActiveSeedsWithoutJob() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	count := 0
	for _, metrics := range sr.seeds {
		if metrics.IsActive && metrics.CurrentJobID == "" {
			count++
		}
	}
	return count
}
