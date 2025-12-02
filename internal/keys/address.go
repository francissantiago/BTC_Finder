package keys

import (
    "crypto/sha256"
    "fmt"

    "github.com/btcsuite/btcutil/base58"
    "golang.org/x/crypto/ripemd160"
)

// AddressFromPubKey converts a public key byte slice into a Bitcoin address (Base58, mainnet).
func AddressFromPubKey(pub []byte) (string, error) {
    if len(pub) == 0 {
        return "", fmt.Errorf("public key is empty")
    }

    // SHA-256 of the public key
    sha := sha256.Sum256(pub)

    // RIPEMD-160 of the SHA-256
    ripemd := ripemd160.New()
    _, _ = ripemd.Write(sha[:])
    hashedPub := ripemd.Sum(nil)

    // Version byte: 0x00 for mainnet
    versionedPayload := append([]byte{0x00}, hashedPub...)

    // Double SHA-256 checksum
    first := sha256.Sum256(versionedPayload)
    second := sha256.Sum256(first[:])
    checksum := second[:4]

    // Final binary address
    binaryAddress := append(versionedPayload, checksum...)

    // Base58 encode
    addr := base58.Encode(binaryAddress)
    return addr, nil
}

