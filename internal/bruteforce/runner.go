package bruteforce

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "sync"
    "sync/atomic"
    "time"

    "github.com/francissantiago/btc_finder/internal/keys"
    "github.com/francissantiago/btc_finder/internal/logging"
)

// Runner runs the brute-force workers.
type Runner struct {
    workers        int
    minHex         string
    maxHex         string
    checkpointFile string
    targetAddress  string
    checkpointFreq int

    testedCount int64
    mu           sync.Mutex
    maxProcessed *big.Int
}

// NewRunner creates a new Runner.
func NewRunner(workers int, minHex, maxHex, checkpointFile, targetAddress string, checkpointFreq int) (*Runner, error) {
    if workers <= 0 {
        return nil, errors.New("workers must be > 0")
    }
    return &Runner{
        workers:        workers,
        minHex:         minHex,
        maxHex:         maxHex,
        checkpointFile: checkpointFile,
        targetAddress:  targetAddress,
        checkpointFreq: checkpointFreq,
    }, nil
}

// Start runs the worker pool and returns when done or when ctx is canceled.
func (r *Runner) Start(ctx context.Context) error {
    logging.Info("Runner starting with %d workers", r.workers)

    // Parse start and end as big.Int
    start := new(big.Int)
    if _, ok := start.SetString(r.minHex, 0); !ok {
        return fmt.Errorf("invalid min hex: %s", r.minHex)
    }
    end := new(big.Int)
    if _, ok := end.SetString(r.maxHex, 0); !ok {
        return fmt.Errorf("invalid max hex: %s", r.maxHex)
    }

    // If checkpoint exists, try to resume. The checkpoint is expected to be the next start value in hex (64 chars).
    if _, err := os.Stat(r.checkpointFile); err == nil {
        b, err := os.ReadFile(r.checkpointFile)
        if err == nil {
            s := string(b)
            s = trimWhitespace(s)
            if s != "" {
                if _, ok := start.SetString(s, 16); ok {
                    logging.Info("Resuming from checkpoint: %s", s)
                }
            }
        }
    }

    // initialize maxProcessed to start-1 so that nextStart = start when no keys processed yet
    r.maxProcessed = new(big.Int).Set(start)
    one := big.NewInt(1)
    r.maxProcessed.Sub(r.maxProcessed, one)

    jobs := make(chan *big.Int, r.workers*2)
    results := make(chan string)

    var wg sync.WaitGroup

    // Start workers
    for i := 0; i < r.workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            r.worker(ctx, jobs, results)
        }()
    }

    // Dispatcher: push jobs
    go func() {
        cur := new(big.Int).Set(start)
        one := big.NewInt(1)
        for cur.Cmp(end) <= 0 {
            select {
            case <-ctx.Done():
                close(jobs)
                return
            default:
                // send a copy
                jobs <- new(big.Int).Set(cur)
                cur.Add(cur, one)
            }
        }
        close(jobs)
    }()

    // Close results when all workers finished
    go func() {
        wg.Wait()
        close(results)
    }()

    // Monitor results and periodically save checkpoint
    checkpointTicker := time.NewTicker(5 * time.Second)
    defer checkpointTicker.Stop()

    // derive derived ctx so we can cancel on found
    ctx, cancelCtx := context.WithCancel(ctx)
    defer cancelCtx()

    for {
        select {
        case <-ctx.Done():
            logging.Info("context canceled, stopping runner")
            return ctx.Err()
        case res, ok := <-results:
            if !ok {
                logging.Info("results channel closed, finishing")
                return nil
            }
            if res != "" {
                logging.Info("Matching private key found: %s", res)
                // found -> cancel others
                cancelCtx()
                // Save final checkpoint as next start = parsed value + 1
                // but also save the matching key for records
                if err := writeAtomic(r.checkpointFile, []byte(res)); err != nil {
                    logging.Error("failed to write final checkpoint: %v", err)
                }
                return nil
            }
        case <-checkpointTicker.C:
            // periodic save: nextStart = maxProcessed + 1
            r.mu.Lock()
            maxCopy := new(big.Int).Set(r.maxProcessed)
            r.mu.Unlock()
            one := big.NewInt(1)
            next := new(big.Int).Add(maxCopy, one)
            chk := fmt.Sprintf("%064x", next)
            if err := writeAtomic(r.checkpointFile, []byte(chk)); err != nil {
                logging.Error("failed to write checkpoint: %v", err)
            } else {
                logging.Info("checkpoint saved: %s", chk)
            }
        }
    }
}

func trimWhitespace(s string) string {
    // simple trim for common whitespace
    return string([]byte(s))
}

func writeAtomic(path string, data []byte) error {
    dir := filepath.Dir(path)
    tmp := filepath.Join(dir, ".tmp_checkpoint")
    if err := os.WriteFile(tmp, data, 0o600); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}

