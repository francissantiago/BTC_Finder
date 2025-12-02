package keys

import (
    "fmt"
    "github.com/btcsuite/btcd/btcec/v2"
)

// GeneratePubKey receives a 32-byte private key and returns a compressed public key (33 bytes).
func GeneratePubKey(priv []byte) ([]byte, error) {
    if len(priv) != 32 {
        return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(priv))
    }
    sk, _ := btcec.PrivKeyFromBytes(priv)
    pub := sk.PubKey().SerializeCompressed()
    return pub, nil
}

// AddressFromPrivate is a convenience helper to produce a Bitcoin address directly from a 32-byte privkey.
func AddressFromPrivate(priv []byte) (string, error) {
    pub, err := GeneratePubKey(priv)
    if err != nil {
        return "", err
    }
    return AddressFromPubKey(pub)
}
