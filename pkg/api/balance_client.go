package api

import (
    "context"
    "time"
)

// BalanceClient is a simple client to fetch balance for an address.
type BalanceClient struct{
    // TODO: add HTTP client, timeouts, backoff config
}

// NewBalanceClient returns a new BalanceClient skeleton.
func NewBalanceClient() *BalanceClient {
    return &BalanceClient{}
}

// GetBalance returns balance in satoshis for the provided address (stub).
func (c *BalanceClient) GetBalance(ctx context.Context, address string) (int64, error) {
    // TODO: implement HTTP call to blockchain.info or configurable provider
    _ = ctx
    _ = address
    time.Sleep(10 * time.Millisecond)
    return 0, nil
}
