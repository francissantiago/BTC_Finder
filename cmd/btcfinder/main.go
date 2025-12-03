package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/francissantiago/btc_finder/internal/bruteforce"
	"github.com/francissantiago/btc_finder/internal/logging"
	"github.com/francissantiago/btc_finder/internal/node"
	"github.com/francissantiago/btc_finder/internal/seed"
	"github.com/francissantiago/btc_finder/internal/storage"
)

func main() {
	var (
		mode = flag.String("mode", "local", "execution mode: local, node, or seed")

		// Common flags
		workers = flag.Int("workers", runtime.NumCPU(), "number of workers")
		address = flag.String("address", "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY", "target Bitcoin address")

		// Local/Seed mode flags
		minHex         = flag.String("min", "0x8000", "minimum private key hex (ex: 0x8000)")
		maxHex         = flag.String("max", "0xffff", "maximum private key hex (ex: 0xffff)")
		checkpointFile = flag.String("checkpoint", "checkpoint.txt", "checkpoint file path")
		checkpointFreq = flag.Int("checkpoint-freq", 1000, "checkpoint save frequency (in checked keys)")

		// Node mode flags
		nodePort  = flag.String("port", ":8080", "node server port")
		numSeeds  = flag.Int("num-seeds", 4, "expected number of seeds")
		jobSize   = flag.Int("job-size", 0, "job size in number of keys (0 = divide by num-seeds)")
		nodeToken = flag.String("node-token", "secret-token", "node authentication token")
		dbPath    = flag.String("db", "btc_finder.db", "database path for node")

		// Seed mode flags
		nodeURL   = flag.String("node-url", "http://localhost:8080", "node server URL")
		seedToken = flag.String("seed-token", "secret-token", "seed authentication token")
		seedID    = flag.String("seed-id", "", "seed identifier")

		// Telegram flags
		telegramBotToken = flag.String("telegram-bot-token", "", "Telegram bot token")
		telegramChatID   = flag.String("telegram-chat-id", "", "Telegram chat ID")
	)

	flag.Parse()

	logging.Info("BTC Finder (Go) starting in %s mode", *mode)

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		logging.Info("signal received, canceling...")
		cancel()
	}()

	switch *mode {
	case "local":
		runLocalMode(ctx, *workers, *minHex, *maxHex, *checkpointFile, *address, *checkpointFreq)

	case "node":
		if *seedID == "" {
			*seedID = fmt.Sprintf("node-%d", time.Now().Unix())
		}
		runNodeMode(ctx, *nodePort, *nodeToken, *numSeeds, *jobSize, *minHex, *maxHex, *address, *dbPath, *telegramBotToken, *telegramChatID)

	case "seed":
		if *seedID == "" {
			*seedID = fmt.Sprintf("seed-%d", time.Now().Unix())
		}
		runSeedMode(ctx, *seedID, *nodeURL, *seedToken, *workers, *address, *checkpointFile, *checkpointFreq)

	default:
		fmt.Printf("unknown mode: %s (use local, node, or seed)\n", *mode)
		os.Exit(1)
	}

	logging.Info("application finished")
	time.Sleep(100 * time.Millisecond)
}

// runLocalMode runs the local brute-force mode (original behavior)
func runLocalMode(ctx context.Context, workers int, minHex, maxHex, checkpointFile, targetAddress string, checkpointFreq int) {
	logging.Info("Running in LOCAL mode")
	logging.Info("Workers: %d", workers)
	logging.Info("Range: %s - %s", minHex, maxHex)

	r, err := bruteforce.NewRunner(workers, minHex, maxHex, checkpointFile, targetAddress, checkpointFreq)
	if err != nil {
		fmt.Println("failed to create runner:", err)
		os.Exit(1)
	}

	if err := r.Start(ctx); err != nil {
		logging.Error("runner finished with error: %v", err)
		os.Exit(1)
	}
}

// runNodeMode runs the node server mode
func runNodeMode(ctx context.Context, port, token string, numSeeds, jobSize int, minHex, maxHex, targetAddress, dbPath, telegramBotToken, telegramChatID string) {
	logging.Info("Running in NODE mode")
	logging.Info("Port: %s, Expected seeds: %d", port, numSeeds)
	logging.Info("Range: %s - %s", minHex, maxHex)

	// Calculate number of jobs
	numJobs := numSeeds
	if jobSize > 0 {
		// Calculate based on job size
		minVal := new(big.Int)
		maxVal := new(big.Int)
		if _, ok := minVal.SetString(minHex, 0); !ok {
			logging.Error("invalid minHex: %s", minHex)
			os.Exit(1)
		}
		if _, ok := maxVal.SetString(maxHex, 0); !ok {
			logging.Error("invalid maxHex: %s", maxHex)
			os.Exit(1)
		}
		totalKeys := new(big.Int).Sub(maxVal, minVal)
		totalKeys.Add(totalKeys, big.NewInt(1)) // inclusive
		numJobsBig := new(big.Int).Div(totalKeys, big.NewInt(int64(jobSize)))
		if numJobsBig.Cmp(big.NewInt(0)) == 0 {
			numJobs = 1
		} else {
			// Check if numJobsBig fits in int
			maxInt := big.NewInt(int64(^uint(0) >> 1))
			if numJobsBig.Cmp(maxInt) > 0 {
				logging.Error("Too many jobs calculated (%s), range too large", numJobsBig.String())
				os.Exit(1)
			}
			numJobs = int(numJobsBig.Int64())
			// Limit maximum jobs to prevent memory issues
			const maxJobs = 100
			if numJobs > maxJobs {
				logging.Warn("Calculated jobs (%d) exceeds maximum (%d), limiting to %d", numJobs, maxJobs, maxJobs)
				numJobs = maxJobs
			}
		}
		logging.Info("Job size: %d keys, Total jobs: %d", jobSize, numJobs)
	}

	// Initialize database
	store, err := storage.NewSQLiteStorage(dbPath)
	if err != nil {
		logging.Error("failed to initialize database: %v", err)
		os.Exit(1)
	}
	defer store.Close()

	// Create and start node server
	nodeServer := node.NewServer(port, token, store, targetAddress, telegramBotToken, telegramChatID)

	// Create initial jobs
	jobs, err := nodeServer.GetJobManager().CreateJobsFromRange(minHex, maxHex, numJobs)
	if err != nil {
		logging.Error("failed to create jobs: %v", err)
		os.Exit(1)
	}
	logging.Info("created %d jobs", len(jobs))

	// Start server (blocking)
	if err := nodeServer.Start(ctx); err != nil {
		logging.Error("node server error: %v", err)
		os.Exit(1)
	}
}

// runSeedMode runs the seed client mode
func runSeedMode(ctx context.Context, seedID, nodeURL, token string, workers int, targetAddress, checkpointFile string, checkpointFreq int) {
	logging.Info("Running in SEED mode")
	logging.Info("Seed ID: %s, Node URL: %s, Workers: %d", seedID, nodeURL, workers)
	logging.Info("Target address: %s", targetAddress)

	// Create seed client and start requesting/processing jobs
	seedClient := seed.NewClient(seedID, nodeURL, token)
	if err := seedClient.Start(ctx, workers, targetAddress, checkpointFile, checkpointFreq); err != nil {
		logging.Error("seed client error: %v", err)
		os.Exit(1)
	}
}
