package pkclient

import (
	"fmt"
	"testing"
)

const PIN = "3537363231383830"
const PKCS11_LIB = "/usr/lib/pkcs11/opensc-pkcs11.so"
const SLOT = 0

func TestPKClient(t *testing.T) {
	client, err := NewHSM(PKCS11_LIB, SLOT, PIN)
	if err != nil {
		t.Errorf("Error loading module: %w\n", err)
		return
	}
	fmt.Println("Success!")
	fmt.Printf("client: %v\n", *client)
	key, err := client.PublicKey()
	if err != nil {
		t.Errorf("Error getting public key: %w\n", err)
		return
	}
	var buf [32]byte
	copy(buf[:], key[:32])
	buf, err = client.DeriveNoise(buf)
	if err != nil {
		t.Errorf("Error performing derive: %w\n", err)
		return
	}
	fmt.Printf("public key: %v\n", key)
	fmt.Printf("secret: %v\n", buf)
}
