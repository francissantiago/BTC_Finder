package seed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/francissantiago/btc_finder/internal/bruteforce"
	"github.com/francissantiago/btc_finder/internal/keys"
	"github.com/francissantiago/btc_finder/internal/logging"
	"github.com/francissantiago/btc_finder/internal/models"
)

// Client represents a seed that connects to a node
type Client struct {
	seedID       string
	nodeURL      string
	token        string
	httpClient   *http.Client
	statusTicker *time.Ticker
	retryWait    time.Duration
}

// NewClient creates a new seed client
func NewClient(seedID, nodeURL, token string) *Client {
	return &Client{
		seedID:     seedID,
		nodeURL:    nodeURL,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		retryWait:  5 * time.Second,
	}
}

// RequestJob requests a job from the node
func (c *Client) RequestJob(ctx context.Context, numWorkers int) (*models.Job, error) {
	req := models.JobRequest{
		SeedID:     c.seedID,
		NumWorkers: numWorkers,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/jobs/request", c.nodeURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to request job: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, fmt.Errorf("no jobs available")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var jobResp models.JobResponse
	if err := json.NewDecoder(resp.Body).Decode(&jobResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return jobResp.Job, nil
}

// ReportProgress reports job progress to the node
func (c *Client) ReportProgress(ctx context.Context, jobID string, keysChecked int64, lastChecksum string, keysPerSecond float64, estimatedTimeLeft int) error {
	update := models.JobStatusUpdate{
		JobID:             jobID,
		SeedID:            c.seedID,
		KeysChecked:       keysChecked,
		LastChecksum:      lastChecksum,
		KeysPerSecond:     keysPerSecond,
		EstimatedTimeLeft: estimatedTimeLeft,
	}

	body, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/jobs/status", c.nodeURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to report progress: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ReportMatch reports a found private key match to the node
func (c *Client) ReportMatch(ctx context.Context, jobID string, privateKey, address, targetAddress string, keysCheckedUntil int64) error {
	alert := models.MatchAlert{
		JobID:            jobID,
		SeedID:           c.seedID,
		PrivateKey:       privateKey,
		Address:          address,
		TargetAddress:    targetAddress,
		FoundAt:          time.Now(),
		KeysCheckedUntil: keysCheckedUntil,
	}

	body, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/jobs/match", c.nodeURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to report match: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ReportCompletion reports job completion to the node
func (c *Client) ReportCompletion(ctx context.Context, jobID string, keysChecked int64) error {
	completion := models.JobCompletion{
		JobID:       jobID,
		SeedID:      c.seedID,
		Status:      models.JobStatusCompleted,
		KeysChecked: keysChecked,
		CompletedAt: time.Now(),
	}

	body, err := json.Marshal(completion)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/jobs/complete", c.nodeURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to report completion: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ReportFailure reports job failure to the node
func (c *Client) ReportFailure(ctx context.Context, jobID string, errorMessage string) error {
	completion := models.JobCompletion{
		JobID:        jobID,
		SeedID:       c.seedID,
		Status:       models.JobStatusFailed,
		ErrorMessage: errorMessage,
		CompletedAt:  time.Now(),
	}

	body, err := json.Marshal(completion)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/jobs/fail", c.nodeURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to report failure: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RequestJobWithRetry requests a job with exponential backoff retry
func (c *Client) RequestJobWithRetry(ctx context.Context, numWorkers int, maxRetries int) (*models.Job, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * c.retryWait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		job, err := c.RequestJob(ctx, numWorkers)
		if err == nil {
			return job, nil
		}

		lastErr = err
		logging.Debug("failed to request job (attempt %d/%d): %v", attempt+1, maxRetries, err)
	}

	return nil, fmt.Errorf("failed to request job after %d attempts: %w", maxRetries, lastErr)
}

// ReportProgressPeriodically starts periodic progress reporting
func (c *Client) ReportProgressPeriodically(ctx context.Context, jobID string, progressChan <-chan ProgressUpdate) {
	c.statusTicker = time.NewTicker(10 * time.Second)
	defer c.statusTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-c.statusTicker.C:
			select {
			case progress := <-progressChan:
				if err := c.ReportProgress(ctx, jobID, progress.KeysChecked, progress.LastChecksum, progress.KeysPerSecond, progress.EstimatedTimeLeft); err != nil {
					logging.Error("failed to report progress: %v", err)
				}
			default:
				// No progress update available
			}

		case progress := <-progressChan:
			if err := c.ReportProgress(ctx, jobID, progress.KeysChecked, progress.LastChecksum, progress.KeysPerSecond, progress.EstimatedTimeLeft); err != nil {
				logging.Error("failed to report progress: %v", err)
			}
		}
	}
}

// ProgressUpdate represents a progress update for a job
type ProgressUpdate struct {
	KeysChecked       int64
	LastChecksum      string
	KeysPerSecond     float64
	EstimatedTimeLeft int
}

// Start begins the seed worker loop requesting and processing jobs
func (c *Client) Start(ctx context.Context, workers int, targetAddress, checkpointFile string, checkpointFreq int) error {
	logging.Info("Seed client starting: seedID=%s, workers=%d", c.seedID, workers)

	for {
		select {
		case <-ctx.Done():
			logging.Info("Seed client context canceled")
			return ctx.Err()
		default:
		}

		// Request a job from the node with retry
		logging.Info("Requesting job from node...")
		job, err := c.RequestJobWithRetry(ctx, workers, 5)
		if err != nil {
			logging.Error("Failed to get job after retries: %v, waiting before retry...", err)
			select {
			case <-time.After(30 * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if job == nil {
			logging.Info("No jobs available, waiting before retry...")
			select {
			case <-time.After(10 * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		logging.Info("Received job %s: range %s - %s", job.ID, job.MinHex, job.MaxHex)

		// Process the job
		found, keysChecked, err := c.processJob(ctx, job, workers, targetAddress, checkpointFile, checkpointFreq)
		if err != nil {
			logging.Error("Error processing job %s: %v", job.ID, err)
			c.ReportFailure(ctx, job.ID, err.Error())
			continue
		}

		if found {
			logging.Info("Match found! Seed is stopping.")
			return nil
		}

		// Job completed without finding the key
		logging.Info("Job %s completed without match, requesting next job", job.ID)
		c.ReportCompletion(ctx, job.ID, keysChecked)
	}
}

// processJob runs bruteforce for a job and returns true if match found and keys checked
func (c *Client) processJob(ctx context.Context, job *models.Job, workers int, targetAddress, checkpointFile string, checkpointFreq int) (bool, int64, error) {
	logging.Info("Processing job %s with %d workers", job.ID, workers)

	// Create a runner for this job's range
	runner, err := bruteforce.NewRunner(
		workers,
		job.MinHex,
		job.MaxHex,
		"", // No checkpoint in distributed mode
		targetAddress,
		checkpointFreq,
	)
	if err != nil {
		return false, 0, err
	}

	// Channel to receive match result
	foundChan := make(chan bool, 1)
	var lastKeysChecked int64

	// Start bruteforce with callback
	go func() {
		err := runner.StartWithCallback(ctx, func(privateKey string) {
			logging.Info("FOUND! Private key: %s", privateKey)

			// Derive address and report to node
			if addr, err := deriveAddress(privateKey); err == nil {
				if err := c.ReportMatch(ctx, job.ID, privateKey, addr, targetAddress, lastKeysChecked); err != nil {
					logging.Error("Failed to report match to node: %v", err)
				}
			}

			foundChan <- true
		}, func(keysChecked int64, lastChecksum string) {
			lastKeysChecked = keysChecked
			// Report progress to node
			if err := c.ReportProgress(ctx, job.ID, keysChecked, lastChecksum, 0, 0); err != nil {
				logging.Error("Failed to report progress: %v", err)
			}
		})

		if err != nil && err != context.Canceled {
			logging.Error("Runner error: %v", err)
		}

		select {
		case <-foundChan:
			// Already sent
		default:
			foundChan <- false
		}
	}()

	// Wait for result
	select {
	case <-ctx.Done():
		return false, lastKeysChecked, ctx.Err()
	case found := <-foundChan:
		return found, lastKeysChecked, nil
	}
}

// deriveAddress derives Bitcoin address from hex private key
func deriveAddress(privateKeyHex string) (string, error) {
	pk := new(big.Int)
	if _, ok := pk.SetString(privateKeyHex, 16); !ok {
		return "", fmt.Errorf("invalid hex private key: %s", privateKeyHex)
	}

	// Convert to 32 bytes
	pkBytes := make([]byte, 32)
	for i, b := range pk.Bytes() {
		pkBytes[32-len(pk.Bytes())+i] = b
	}

	return keys.AddressFromPrivate(pkBytes)
}
