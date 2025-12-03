package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/francissantiago/btc_finder/internal/auth"
	"github.com/francissantiago/btc_finder/internal/logging"
	"github.com/francissantiago/btc_finder/internal/models"
	"github.com/francissantiago/btc_finder/internal/notifications"
	"github.com/francissantiago/btc_finder/internal/storage"
)

// Server represents the Node HTTP server
type Server struct {
	addr         string
	token        string
	jobManager   *JobManager
	seedRegistry *SeedRegistry
	notifier     *notifications.TelegramNotifier
	validator    *auth.BearerTokenValidator
	mux          *http.ServeMux
}

// NewServer creates a new Node server
func NewServer(
	addr, token string,
	store storage.Storage,
	targetAddress string,
	telegramBotToken, telegramChatID string,
) *Server {
	server := &Server{
		addr:         addr,
		token:        token,
		jobManager:   NewJobManager(store, targetAddress),
		seedRegistry: NewSeedRegistry(store),
		notifier:     notifications.NewTelegramNotifier(telegramBotToken, telegramChatID),
		validator:    auth.NewBearerTokenValidator(token),
		mux:          http.NewServeMux(),
	}

	// Register routes
	server.registerRoutes()

	return server
}

// GetJobManager returns the job manager instance
func (s *Server) GetJobManager() *JobManager {
	return s.jobManager
}

// registerRoutes registers HTTP endpoints
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/jobs/request", s.validator.Middleware(http.HandlerFunc(s.handleJobRequest)).ServeHTTP)
	s.mux.HandleFunc("/jobs/status", s.validator.Middleware(http.HandlerFunc(s.handleJobStatus)).ServeHTTP)
	s.mux.HandleFunc("/jobs/match", s.validator.Middleware(http.HandlerFunc(s.handleJobMatch)).ServeHTTP)
	s.mux.HandleFunc("/jobs/complete", s.validator.Middleware(http.HandlerFunc(s.handleJobComplete)).ServeHTTP)
	s.mux.HandleFunc("/jobs/fail", s.validator.Middleware(http.HandlerFunc(s.handleJobFail)).ServeHTTP)
	s.mux.HandleFunc("/seeds/status", s.validator.Middleware(http.HandlerFunc(s.handleSeedStatus)).ServeHTTP)
	s.mux.HandleFunc("/metrics", s.validator.Middleware(http.HandlerFunc(s.handleMetrics)).ServeHTTP)
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	logging.Info("Node server starting on %s", s.addr)

	server := &http.Server{
		Addr:    s.addr,
		Handler: s.mux,
	}

	// Channel to signal when server is done
	done := make(chan error, 1)

	go func() {
		done <- server.ListenAndServe()
	}()

	// Wait for context cancellation or server error
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		logging.Info("Shutting down server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logging.Error("Server shutdown error: %v", err)
			return err
		}
		logging.Info("Server shutdown complete")
		return nil
	}
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})
}

// handleJobRequest handles seed request for a job
func (s *Server) handleJobRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.JobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.SeedID == "" {
		http.Error(w, "seed_id required", http.StatusBadRequest)
		return
	}

	// Register seed if not already registered
	if _, err := s.seedRegistry.RegisterSeed(req.SeedID); err != nil {
		logging.Error("failed to register seed %s: %v", req.SeedID, err)
		http.Error(w, "failed to register seed", http.StatusInternalServerError)
		return
	}

	// Request a job
	job, err := s.jobManager.RequestJob(req.SeedID)
	if err != nil {
		logging.Warn("no job available for seed %s: %v", req.SeedID, err)
		http.Error(w, "no jobs available", http.StatusNoContent)
		return
	}

	// Set current job for seed
	s.seedRegistry.SetCurrentJob(req.SeedID, job.ID)

	// Return job
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.JobResponse{
		Job:   job,
		Token: s.token,
	})

	logging.Info("assigned job %s to seed %s", job.ID, req.SeedID)
}

// handleJobStatus handles job progress updates from seeds
func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var update models.JobStatusUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if update.JobID == "" || update.SeedID == "" {
		http.Error(w, "job_id and seed_id required", http.StatusBadRequest)
		return
	}

	// Update job progress
	if err := s.jobManager.UpdateJobProgress(update.JobID, update.KeysChecked, update.LastChecksum); err != nil {
		logging.Error("failed to update job progress: %v", err)
		http.Error(w, "failed to update job progress", http.StatusInternalServerError)
		return
	}

	// Update seed metrics
	if update.KeysPerSecond > 0 {
		metrics, _ := s.seedRegistry.GetSeedMetrics(update.SeedID)
		if metrics != nil {
			s.seedRegistry.UpdateSeedMetrics(update.SeedID, metrics.JobsCompleted, metrics.JobsFailed, update.KeysPerSecond)
		}
	}

	// Update heartbeat
	s.seedRegistry.UpdateHeartbeat(update.SeedID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})

	logging.Debug("job %s status updated by seed %s: %d keys checked", update.JobID, update.SeedID, update.KeysChecked)
}

// handleJobMatch handles a match found by a seed
func (s *Server) handleJobMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var alert models.MatchAlert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if alert.JobID == "" || alert.SeedID == "" {
		http.Error(w, "job_id and seed_id required", http.StatusBadRequest)
		return
	}

	logging.Info("MATCH FOUND! Job: %s, Seed: %s, Address: %s", alert.JobID, alert.SeedID, alert.Address)

	// Send Telegram notification
	if s.notifier.IsConfigured() {
		if err := s.notifier.SendMatchAlert(alert.Address, alert.PrivateKey, alert.TargetAddress); err != nil {
			logging.Error("failed to send Telegram notification: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})
}

// handleJobComplete handles job completion
func (s *Server) handleJobComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var completion models.JobCompletion
	if err := json.NewDecoder(r.Body).Decode(&completion); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if completion.JobID == "" || completion.SeedID == "" {
		http.Error(w, "job_id and seed_id required", http.StatusBadRequest)
		return
	}

	// Complete job
	if err := s.jobManager.CompleteJob(completion.JobID, completion.KeysChecked); err != nil {
		logging.Error("failed to complete job: %v", err)
		http.Error(w, "failed to complete job", http.StatusInternalServerError)
		return
	}

	// Update seed metrics
	metrics, _ := s.seedRegistry.GetSeedMetrics(completion.SeedID)
	if metrics != nil {
		s.seedRegistry.UpdateSeedMetrics(completion.SeedID, metrics.JobsCompleted+1, metrics.JobsFailed, metrics.LastKeysPerSecond)
	}

	s.seedRegistry.SetCurrentJob(completion.SeedID, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})

	logging.Info("job %s completed by seed %s (%d keys checked)", completion.JobID, completion.SeedID, completion.KeysChecked)

	// Check if should rebalance
	s.checkAndRebalance()
}

// handleJobFail handles job failure
func (s *Server) handleJobFail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var completion models.JobCompletion
	if err := json.NewDecoder(r.Body).Decode(&completion); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if completion.JobID == "" || completion.SeedID == "" {
		http.Error(w, "job_id and seed_id required", http.StatusBadRequest)
		return
	}

	// Fail job
	if err := s.jobManager.FailJob(completion.JobID); err != nil {
		logging.Error("failed to mark job as failed: %v", err)
		http.Error(w, "failed to mark job as failed", http.StatusInternalServerError)
		return
	}

	// Update seed metrics
	metrics, _ := s.seedRegistry.GetSeedMetrics(completion.SeedID)
	if metrics != nil {
		s.seedRegistry.UpdateSeedMetrics(completion.SeedID, metrics.JobsCompleted, metrics.JobsFailed+1, metrics.LastKeysPerSecond)
	}

	s.seedRegistry.SetCurrentJob(completion.SeedID, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})

	logging.Error("job %s failed by seed %s: %s", completion.JobID, completion.SeedID, completion.ErrorMessage)
}

// handleSeedStatus handles seed status reporting
func (s *Server) handleSeedStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SeedID string `json:"seed_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.SeedID == "" {
		http.Error(w, "seed_id required", http.StatusBadRequest)
		return
	}

	// Update heartbeat
	s.seedRegistry.UpdateHeartbeat(req.SeedID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})
}

// handleMetrics returns server metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pendingJobs, _ := s.jobManager.ListPendingJobs()
	assignedJobs, _ := s.jobManager.ListAssignedJobs()
	inProgressJobs, _ := s.jobManager.ListInProgressJobs()
	activeSeedsMetrics, _ := s.seedRegistry.ListActiveSeedMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pending_jobs":     len(pendingJobs),
		"assigned_jobs":    len(assignedJobs),
		"in_progress_jobs": len(inProgressJobs),
		"active_seeds":     len(activeSeedsMetrics),
		"seeds_metrics":    activeSeedsMetrics,
		"timestamp":        time.Now(),
	})
}

// checkAndRebalance checks if rebalancing is needed
func (s *Server) checkAndRebalance() {
	// Check if all jobs are done except one slow seed
	inProgressJobs, err := s.jobManager.ListInProgressJobs()
	if err != nil || len(inProgressJobs) != 1 {
		return
	}

	// Get slow seed
	slowSeed, err := s.seedRegistry.GetSlowSeedWithActiveJob()
	if err != nil {
		return
	}

	// Count seeds waiting for jobs
	waitingSeedsCount := s.seedRegistry.CountActiveSeedsWithoutJob()
	if waitingSeedsCount == 0 {
		return
	}

	logging.Info("rebalancing: subdividing job %s from slow seed %s into %d parts for %d waiting seeds",
		inProgressJobs[0].ID, slowSeed.SeedID, waitingSeedsCount, waitingSeedsCount)

	// Subdivide and requeue
	if err := s.jobManager.SubdivideJobAndRequeue(inProgressJobs[0].ID, waitingSeedsCount); err != nil {
		logging.Error("failed to rebalance job: %v", err)
	}
}

// ExtractBearerToken extracts token from Authorization header
func ExtractBearerToken(authHeader string) string {
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}
