package keys

import (
    "encoding/hex"
    "testing"
)

// Test vector: private key = 1 -> address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
func TestAddressFromPrivate_Vector1(t *testing.T) {
    privHex := "0000000000000000000000000000000000000000000000000000000000000001"
    priv, err := hex.DecodeString(privHex)
    if err != nil {
        t.Fatalf("failed to decode priv hex: %v", err)
    }

    addr, err := AddressFromPrivate(priv)
    if err != nil {
        t.Fatalf("AddressFromPrivate returned error: %v", err)
    }

    want := "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    if addr != want {
        t.Fatalf("unexpected address: got %s want %s", addr, want)
    }
}
