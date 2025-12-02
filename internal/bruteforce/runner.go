package bruteforce

import (
    "context"
    "fmt"
)

// Runner is a skeleton for the brute-force runner.
type Runner struct {
    Workers int
}

// NewRunner creates a new Runner with the given number of workers.
func NewRunner(workers int) *Runner {
    return &Runner{Workers: workers}
}

// Start starts the runner (placeholder implementation).
func (r *Runner) Start(ctx context.Context) error {
    fmt.Printf("Runner started with %d workers (placeholder)\n", r.Workers)
    // TODO: implement worker pool, batching, checkpointing
    select {
    case <-ctx.Done():
        fmt.Println("Runner canceled")
        return ctx.Err()
    default:
        return nil
    }
}
