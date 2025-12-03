package bruteforce

import (
    "context"
    "encoding/hex"
    "math/big"

    "github.com/francissantiago/btc_finder/internal/keys"
    "github.com/francissantiago/btc_finder/internal/logging"
)

func (r *Runner) worker(ctx context.Context, jobs <-chan *big.Int, results chan<- string) {
    for {
        select {
        case <-ctx.Done():
            return
        case n, ok := <-jobs:
            if !ok {
                return
            }
            // convert big.Int to 32-byte slice
            b := n.Bytes()
            // pad to 32 bytes
            priv := make([]byte, 32)
            copy(priv[32-len(b):], b)

            addr, err := keys.AddressFromPrivate(priv)
            if err != nil {
                logging.Error("error generating address: %v", err)
                continue
            }

            // update maxProcessed to the highest processed value
            r.mu.Lock()
            if r.maxProcessed == nil {
                r.maxProcessed = new(big.Int).Set(n)
            } else if n.Cmp(r.maxProcessed) > 0 {
                r.maxProcessed.Set(n)
            }
            r.mu.Unlock()

            // increment tested count
            r.mu.Lock()
            r.testedCount++
            r.mu.Unlock()

            if addr == r.targetAddress {
                // return hex private key
                hexpk := hex.EncodeToString(priv)
                select {
                case results <- hexpk:
                case <-ctx.Done():
                }
                return
            }
            // no match: do not flood results channel; just continue
        }
    }
}

