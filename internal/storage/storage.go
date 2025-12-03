package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/francissantiago/btc_finder/internal/models"
	_ "modernc.org/sqlite"
)

// Storage interface defines methods for persisting data
type Storage interface {
	// Job operations
	SaveJob(job *models.Job) error
	GetJob(jobID string) (*models.Job, error)
	ListJobs(status models.JobStatus, limit int) ([]*models.Job, error)
	UpdateJobStatus(jobID string, status models.JobStatus, keysChecked int64, lastChecksum string) error
	UpdateJobAssignment(jobID string, seedID string) error
	ListJobsByStatus(status models.JobStatus) ([]*models.Job, error)

	// Seed metrics operations
	SaveSeedMetrics(metrics *models.SeedMetrics) error
	GetSeedMetrics(seedID string) (*models.SeedMetrics, error)
	UpdateSeedMetrics(seedID string, jobsCompleted, jobsFailed int, keysPerSec float64) error
	ListActiveSeedsMetrics() ([]*models.SeedMetrics, error)
	UpdateSeedHeartbeat(seedID string) error

	// Job history
	SaveJobHistory(jobID, seedID string, status models.JobStatus, keysChecked int64) error

	// Cleanup
	Close() error
}

// SQLiteStorage implements Storage interface using SQLite
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite storage
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	storage := &SQLiteStorage{db: db}

	// Run migrations
	if err := storage.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return storage, nil
}

// migrate creates tables if they don't exist
func (s *SQLiteStorage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS jobs (
		id TEXT PRIMARY KEY,
		min_hex TEXT NOT NULL,
		max_hex TEXT NOT NULL,
		target_address TEXT NOT NULL,
		status TEXT NOT NULL,
		assigned_seed TEXT,
		created_at DATETIME NOT NULL,
		assigned_at DATETIME,
		updated_at DATETIME NOT NULL,
		completed_at DATETIME,
		keys_checked INTEGER DEFAULT 0,
		last_checksum TEXT,
		is_subdivided BOOLEAN DEFAULT 0,
		parent_job_id TEXT
	);

	CREATE TABLE IF NOT EXISTS seed_metrics (
		seed_id TEXT PRIMARY KEY,
		current_job_id TEXT,
		jobs_completed INTEGER DEFAULT 0,
		jobs_failed INTEGER DEFAULT 0,
		last_keys_per_second REAL DEFAULT 0,
		last_update_time DATETIME,
		connected_at DATETIME NOT NULL,
		last_heartbeat DATETIME NOT NULL,
		is_active BOOLEAN DEFAULT 1,
		average_send_interval INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS job_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id TEXT NOT NULL,
		seed_id TEXT NOT NULL,
		status TEXT NOT NULL,
		keys_checked INTEGER,
		started_at DATETIME NOT NULL,
		ended_at DATETIME,
		FOREIGN KEY (job_id) REFERENCES jobs(id)
	);

	CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
	CREATE INDEX IF NOT EXISTS idx_jobs_assigned_seed ON jobs(assigned_seed);
	CREATE INDEX IF NOT EXISTS idx_seed_metrics_active ON seed_metrics(is_active);
	CREATE INDEX IF NOT EXISTS idx_job_history_job_id ON job_history(job_id);
	CREATE INDEX IF NOT EXISTS idx_job_history_seed_id ON job_history(seed_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveJob inserts or updates a job
func (s *SQLiteStorage) SaveJob(job *models.Job) error {
	query := `
	INSERT INTO jobs (id, min_hex, max_hex, target_address, status, assigned_seed, 
		created_at, assigned_at, updated_at, completed_at, keys_checked, last_checksum, 
		is_subdivided, parent_job_id)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		assigned_seed = excluded.assigned_seed,
		updated_at = excluded.updated_at,
		completed_at = excluded.completed_at,
		keys_checked = excluded.keys_checked,
		last_checksum = excluded.last_checksum
	`

	_, err := s.db.Exec(query,
		job.ID, job.MinHex, job.MaxHex, job.TargetAddress, job.Status,
		job.AssignedSeed, job.CreatedAt, job.AssignedAt, job.UpdatedAt,
		job.CompletedAt, job.KeysChecked, job.LastChecksum,
		job.IsSubdivided, job.ParentJobID,
	)
	return err
}

// GetJob retrieves a job by ID
func (s *SQLiteStorage) GetJob(jobID string) (*models.Job, error) {
	query := `
	SELECT id, min_hex, max_hex, target_address, status, assigned_seed,
		created_at, assigned_at, updated_at, completed_at, keys_checked, last_checksum,
		is_subdivided, parent_job_id
	FROM jobs WHERE id = ?
	`

	row := s.db.QueryRow(query, jobID)
	job := &models.Job{}

	var assignedAt, completedAt sql.NullTime
	err := row.Scan(&job.ID, &job.MinHex, &job.MaxHex, &job.TargetAddress, &job.Status,
		&job.AssignedSeed, &job.CreatedAt, &assignedAt, &job.UpdatedAt, &completedAt,
		&job.KeysChecked, &job.LastChecksum, &job.IsSubdivided, &job.ParentJobID,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("job not found: %s", jobID)
		}
		return nil, err
	}

	if assignedAt.Valid {
		job.AssignedAt = assignedAt.Time
	}
	if completedAt.Valid {
		job.CompletedAt = completedAt.Time
	}

	return job, nil
}

// ListJobs retrieves jobs by status
func (s *SQLiteStorage) ListJobs(status models.JobStatus, limit int) ([]*models.Job, error) {
	query := `
	SELECT id, min_hex, max_hex, target_address, status, assigned_seed,
		created_at, assigned_at, updated_at, completed_at, keys_checked, last_checksum,
		is_subdivided, parent_job_id
	FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?
	`

	rows, err := s.db.Query(query, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*models.Job
	for rows.Next() {
		job := &models.Job{}
		var assignedAt, completedAt sql.NullTime

		err := rows.Scan(&job.ID, &job.MinHex, &job.MaxHex, &job.TargetAddress, &job.Status,
			&job.AssignedSeed, &job.CreatedAt, &assignedAt, &job.UpdatedAt, &completedAt,
			&job.KeysChecked, &job.LastChecksum, &job.IsSubdivided, &job.ParentJobID,
		)

		if err != nil {
			return nil, err
		}

		if assignedAt.Valid {
			job.AssignedAt = assignedAt.Time
		}
		if completedAt.Valid {
			job.CompletedAt = completedAt.Time
		}

		jobs = append(jobs, job)
	}

	return jobs, rows.Err()
}

// UpdateJobStatus updates job status and progress
func (s *SQLiteStorage) UpdateJobStatus(jobID string, status models.JobStatus, keysChecked int64, lastChecksum string) error {
	query := `
	UPDATE jobs 
	SET status = ?, updated_at = ?, keys_checked = ?, last_checksum = ?
	WHERE id = ?
	`

	_, err := s.db.Exec(query, status, time.Now(), keysChecked, lastChecksum, jobID)
	return err
}

// UpdateJobAssignment assigns a job to a seed
func (s *SQLiteStorage) UpdateJobAssignment(jobID string, seedID string) error {
	query := `
	UPDATE jobs 
	SET status = ?, assigned_seed = ?, assigned_at = ?, updated_at = ?
	WHERE id = ?
	`

	_, err := s.db.Exec(query, models.JobStatusAssigned, seedID, time.Now(), time.Now(), jobID)
	return err
}

// ListJobsByStatus retrieves all jobs with a specific status
func (s *SQLiteStorage) ListJobsByStatus(status models.JobStatus) ([]*models.Job, error) {
	return s.ListJobs(status, 10000) // No practical limit
}

// SaveSeedMetrics saves or updates seed metrics
func (s *SQLiteStorage) SaveSeedMetrics(metrics *models.SeedMetrics) error {
	query := `
	INSERT INTO seed_metrics (seed_id, current_job_id, jobs_completed, jobs_failed,
		last_keys_per_second, last_update_time, connected_at, last_heartbeat, is_active, average_send_interval)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(seed_id) DO UPDATE SET
		current_job_id = excluded.current_job_id,
		jobs_completed = excluded.jobs_completed,
		jobs_failed = excluded.jobs_failed,
		last_keys_per_second = excluded.last_keys_per_second,
		last_update_time = excluded.last_update_time,
		last_heartbeat = excluded.last_heartbeat,
		is_active = excluded.is_active,
		average_send_interval = excluded.average_send_interval
	`

	_, err := s.db.Exec(query,
		metrics.SeedID, metrics.CurrentJobID, metrics.JobsCompleted, metrics.JobsFailed,
		metrics.LastKeysPerSecond, metrics.LastUpdateTime, metrics.ConnectedAt,
		metrics.LastHeartbeat, metrics.IsActive, metrics.AverageSendInterval,
	)
	return err
}

// GetSeedMetrics retrieves seed metrics by ID
func (s *SQLiteStorage) GetSeedMetrics(seedID string) (*models.SeedMetrics, error) {
	query := `
	SELECT seed_id, current_job_id, jobs_completed, jobs_failed, last_keys_per_second,
		last_update_time, connected_at, last_heartbeat, is_active, average_send_interval
	FROM seed_metrics WHERE seed_id = ?
	`

	row := s.db.QueryRow(query, seedID)
	metrics := &models.SeedMetrics{}

	var currentJobID sql.NullString
	var lastUpdateTime, lastHeartbeat sql.NullTime

	err := row.Scan(&metrics.SeedID, &currentJobID, &metrics.JobsCompleted, &metrics.JobsFailed,
		&metrics.LastKeysPerSecond, &lastUpdateTime, &metrics.ConnectedAt, &lastHeartbeat,
		&metrics.IsActive, &metrics.AverageSendInterval,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("seed metrics not found: %s", seedID)
		}
		return nil, err
	}

	if currentJobID.Valid {
		metrics.CurrentJobID = currentJobID.String
	}
	if lastUpdateTime.Valid {
		metrics.LastUpdateTime = lastUpdateTime.Time
	}
	if lastHeartbeat.Valid {
		metrics.LastHeartbeat = lastHeartbeat.Time
	}

	return metrics, nil
}

// UpdateSeedMetrics updates seed performance metrics
func (s *SQLiteStorage) UpdateSeedMetrics(seedID string, jobsCompleted, jobsFailed int, keysPerSec float64) error {
	query := `
	UPDATE seed_metrics
	SET jobs_completed = ?, jobs_failed = ?, last_keys_per_second = ?, last_update_time = ?
	WHERE seed_id = ?
	`

	_, err := s.db.Exec(query, jobsCompleted, jobsFailed, keysPerSec, time.Now(), seedID)
	return err
}

// ListActiveSeedsMetrics retrieves metrics for all active seeds
func (s *SQLiteStorage) ListActiveSeedsMetrics() ([]*models.SeedMetrics, error) {
	query := `
	SELECT seed_id, current_job_id, jobs_completed, jobs_failed, last_keys_per_second,
		last_update_time, connected_at, last_heartbeat, is_active, average_send_interval
	FROM seed_metrics WHERE is_active = 1 ORDER BY last_heartbeat DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allMetrics []*models.SeedMetrics
	for rows.Next() {
		metrics := &models.SeedMetrics{}
		var currentJobID sql.NullString
		var lastUpdateTime, lastHeartbeat sql.NullTime

		err := rows.Scan(&metrics.SeedID, &currentJobID, &metrics.JobsCompleted, &metrics.JobsFailed,
			&metrics.LastKeysPerSecond, &lastUpdateTime, &metrics.ConnectedAt, &lastHeartbeat,
			&metrics.IsActive, &metrics.AverageSendInterval,
		)

		if err != nil {
			return nil, err
		}

		if currentJobID.Valid {
			metrics.CurrentJobID = currentJobID.String
		}
		if lastUpdateTime.Valid {
			metrics.LastUpdateTime = lastUpdateTime.Time
		}
		if lastHeartbeat.Valid {
			metrics.LastHeartbeat = lastHeartbeat.Time
		}

		allMetrics = append(allMetrics, metrics)
	}

	return allMetrics, rows.Err()
}

// UpdateSeedHeartbeat updates the last heartbeat time for a seed
func (s *SQLiteStorage) UpdateSeedHeartbeat(seedID string) error {
	query := `
	UPDATE seed_metrics SET last_heartbeat = ? WHERE seed_id = ?
	`

	_, err := s.db.Exec(query, time.Now(), seedID)
	return err
}

// SaveJobHistory saves a job execution history record
func (s *SQLiteStorage) SaveJobHistory(jobID, seedID string, status models.JobStatus, keysChecked int64) error {
	query := `
	INSERT INTO job_history (job_id, seed_id, status, keys_checked, started_at, ended_at)
	VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query, jobID, seedID, status, keysChecked, time.Now(), time.Now())
	return err
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}
