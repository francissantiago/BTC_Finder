package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "time"
)

func main() {
    var (
        minHex = flag.String("min", "0", "minimum private key hex")
        maxHex = flag.String("max", "f...", "maximum private key hex")
        workers = flag.Int("workers", 4, "number of workers")
    )
    flag.Parse()

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    fmt.Println("BTC Finder (Go) — skeleton")
    fmt.Println("min:", *minHex)
    fmt.Println("max:", *maxHex)
    fmt.Println("workers:", *workers)

    // Placeholder: start runner when implemented
    fmt.Println("Starting runner (placeholder) at", time.Now().Format(time.RFC3339))

    // Keep process alive briefly to simulate work
    select {
    case <-time.After(500 * time.Millisecond):
        fmt.Println("Run complete (placeholder)")
        os.Exit(0)
    case <-ctx.Done():
        fmt.Println("Canceled")
    }
}
