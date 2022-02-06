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
	key, err := client.PublicKeyNoise()
	if err != nil {
		t.Errorf("Error getting public key: %w\n", err)
		return
	}
	bkey := client.PublicKeyB64()
	if err != nil {
		t.Errorf("Error getting public key: %w\n", err)
		return
	}
	fmt.Printf("public bKey: %v\n", bkey)

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

// loads a raw WG key and converts it to a PEM file and write it out
/* func TestFileLoad(t *testing.T) {
	rawWGPK, err := loadRawKey(peerRawWGKey)
	if err != nil {
		t.Errorf("Error loading Raw HW key: %w\n", err)
		return
	}
	fmt.Printf("Raw WG KEY: \n%X\n", rawWGPK)

	//convert the (rawkey back to PEM for testing
	convertedPemKey, err := wgKeyToPem(&rawWGPK, true)
	if err != nil {
		t.Errorf("Error converting key: %w\n", err)
		return
	}

	//fmt.Printf("converted key: %X\n", convertedPemKey)

	encodedStr := base64.StdEncoding.EncodeToString(convertedPemKey)
	fmt.Println("base64 encoded string:")
	fmt.Println(encodedStr)
	encodedByte := []byte(encodedStr)
	writeKeyToPemFile(peerKeyWGPath, encodedByte, true)

} */

/*
func TestLoadPemKeyFileLoad(t *testing.T) {
	key, err := PublicKeyFromFile(knownGoodPEMKey)
	if err != nil {
		t.Errorf("Error loading PEM file: %w\n", err)
		return
	}
	encodedStr := base64.StdEncoding.EncodeToString(key)
	fmt.Println("base64 encoded string:")
	fmt.Println(encodedStr)
	encodedByte := []byte(encodedStr)
	writeKeyToPemFile(convertedPEMKey, encodedByte, true)

}
*/
