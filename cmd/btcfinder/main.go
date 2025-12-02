package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "runtime"
    "syscall"
    "time"

    "github.com/francissantiago/btc_finder/internal/bruteforce"
    "github.com/francissantiago/btc_finder/internal/logging"
)

func main() {
    var (
        minHex         = flag.String("min", "0x8000", "minimum private key hex (ex: 0x8000)")
        maxHex         = flag.String("max", "0xffff", "maximum private key hex (ex: 0xffff)")
        workers        = flag.Int("workers", runtime.NumCPU(), "number of workers")
        checkpointFile = flag.String("checkpoint", "checkpoint.txt", "checkpoint file path")
        targetAddress  = flag.String("address", "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY", "target Bitcoin address")
        checkpointFreq = flag.Int("checkpoint-freq", 1000, "checkpoint save frequency (in checked keys)")
    )
    flag.Parse()

    logging.Info("BTC Finder (Go) starting")
    logging.Info("Workers: %d", *workers)
    logging.Info("Range: %s - %s", *minHex, *maxHex)

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle signals
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigs
        logging.Info("signal received, canceling...")
        cancel()
    }()

    r, err := bruteforce.NewRunner(*workers, *minHex, *maxHex, *checkpointFile, *targetAddress, *checkpointFreq)
    if err != nil {
        fmt.Println("failed to create runner:", err)
        os.Exit(1)
    }

    if err := r.Start(ctx); err != nil {
        logging.Error("runner finished with error: %v", err)
        os.Exit(1)
    }

    logging.Info("runner finished")
    time.Sleep(100 * time.Millisecond)
}

