package bruteforce

import (
    "errors"
)

// ReadCheckpoint reads checkpoint from file (stub).
func ReadCheckpoint(path string) (string, error) {
    // TODO: implement atomic read from file and validate hex length
    return "", errors.New("not implemented")
}

// WriteCheckpoint writes checkpoint to file atomically (stub).
func WriteCheckpoint(path string, hex64 string) error {
    // TODO: implement write tmp + rename for atomicity
    return errors.New("not implemented")
}
