package pkclient

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

const (
	PEM_PUB_HEADER      = "302a300506032b656e032100"
	PEM_PRIV_HEADER     = "302e020100300506032b656e04220420"
	CURVE25519_OID_RAW  = "06032B656E"
	PEM_PUB_KEY_SIZE    = 44
	PEM_PRIV_KEY_SIZE   = 48
	NoisePrivateKeySize = 32
	NoisePublicKeySize  = 32
	ERROR_PUBKEY_HSM    = "error getting public key from hsm"
)

type PKClient struct {
	HSM_Session struct {
		slot       uint        // slot to use on the HSM
		pin        string      // device PIN number
		key_label  string      // label of derivation key. Unused
		key_id     uint        // ID of the key on the device
		session    p11.Session // session object
		pubKey     [NoisePublicKeySize]byte
		PrivKeyObj p11.Object // the private derivation key on the HSM
		PubKeyObj  p11.Object // the public  key on the HSM
	}
}

// right now we don't support user input pins
// TODO add ability to have user enter their pin so we don't save it
// try to open a session with the HSM, select the slot and login to it.
// also try to find an x25519 key to derive with so we can fail early if
// if the program can't derive
func NewHSM(hsm_path string, userDefSlot uint, pin string) (*PKClient, error) {
	client := new(PKClient)

	module, err := p11.OpenModule(hsm_path)
	if err != nil {
		err := fmt.Errorf("failed to load module library: %s", hsm_path)
		return nil, err
	}

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}
	// try to open a session on the slot
	client.HSM_Session.session, err = slots[userDefSlot].OpenWriteSession()
	if err != nil {
		err := fmt.Errorf("failed to open session on slot %d", userDefSlot)
		return nil, err
	}
	client.HSM_Session.slot = userDefSlot
	// login to the slot
	err = client.HSM_Session.session.Login(pin)
	if err != nil {
		fmt.Println("login error, bad pin?", err)
		return nil, err
	}
	//login successful
	client.HSM_Session.pin = pin
	// make sure this device has a private curve25519 key for deriving
	client.HSM_Session.PrivKeyObj, err = client.findDeriveKey(false)
	if err != nil {
		err = fmt.Errorf("failed to find the key for deriving: %w", err)
		return nil, err
	}

	// find the public key of the private key, so we can pass it to a requesting client
	client.HSM_Session.PubKeyObj, err = client.findDeriveKey(true)
	if err != nil {
		err = fmt.Errorf("failed to find public key for deriving")
		return nil, err
	}

	return client, nil
}

// return the public key for the derive key that have previously found
// this will return whole raw value, it's up the caller to check the length
// this will likely be the full EC_POINT. See PublicKeyNoise()
func (client *PKClient) PublicKeyRaw() ([]byte, error) {
	key, err := client.HSM_Session.PubKeyObj.Value()
	if err != nil {
		return key, err
	}
	return key, nil
}

// Returns a 32 byte length key which we attempt to get and convert correctly from the hsm
func (client *PKClient) PublicKeyNoise() (key [NoisePublicKeySize]byte, err error) {
	srcKey, err := client.HSM_Session.PubKeyObj.Value()

	if err != nil || len(srcKey) < NoisePublicKeySize {
		var zkey [NoisePublicKeySize]byte // temp garbage key so we can return the error
		return zkey, err
	}
	// On a Nitrokey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
	// so if it's > 32 bytes, just return the last 32 bytes.
	if len(srcKey) > NoisePublicKeySize {
		srcKey = srcKey[len(srcKey)-NoisePublicKeySize:]
	}

	copy(key[:], srcKey[:])
	return key, nil
}

// Returns a base64 encoded public key
func (client *PKClient) PublicKeyB64() string {
	srcKey, err := client.PublicKeyNoise()
	if err != nil {
		return ERROR_PUBKEY_HSM
	}
	return base64.StdEncoding.EncodeToString(srcKey[:])
}

// Import a PEM formatted curve25519 public key from filePath
// return the raw bytes for use by callers which use raw keys
func LoadPublicKeyFromFile(filePath string) (key []byte, err error) {
	pemFile, err := loadPemKeyFile(filePath)
	if err != nil {
		return nil, err
	}

	rawKey, err := getRaw25519Key(pemFile)
	if err != nil {
		return nil, err
	}
	copy(key, *rawKey)
	return key, nil
}

// TODO clean this up and reduce code reuse from Derive
func (client *PKClient) DeriveNoise(peerPubKey [NoisePublicKeySize]byte) (secret [NoisePrivateKeySize]byte, err error) {

	var mech_mech uint = pkcs11.CKM_ECDH1_DERIVE

	// before you call derive, you need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// pulled template from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	// setup the parameters which include the peer's public keey
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey[:NoisePublicKeySize])

	var mech *pkcs11.Mechanism = pkcs11.NewMechanism(mech_mech, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	tmpKey, err := p11.PrivateKey(client.HSM_Session.PrivKeyObj).Derive(*mech, attrTemplate)
	if err != nil {
		fmt.Println("Error deriving key")
		return secret, err
	}

	copy(secret[:], tmpKey[:NoisePrivateKeySize])
	return secret, err
}

// derives a secret key on a private key with the peerPubKey parameter
func (client *PKClient) Derive(peerPubKey []byte) ([]byte, error) {
	var mech_mech uint = pkcs11.CKM_ECDH1_DERIVE

	// before you call derive, you need to have an array of attributes which specify the type of
	// key you return, in our case, it's the secret key produced via deriving
	// pulled template from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	// setup the parameters which include the peer's public keey
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey)

	var mech *pkcs11.Mechanism = pkcs11.NewMechanism(mech_mech, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	secret, err := p11.PrivateKey(client.HSM_Session.PrivKeyObj).Derive(*mech, attrTemplate)
	if err != nil {
		fmt.Println("Error deriving key")
		return nil, err
	}
	return secret, nil
}

// skip ASN.1 parsing and just get the last 32 bytes of the key
func getRaw25519Key(srcKey *pem.Block) (*[]byte, error) {
	if srcKey != nil || len(srcKey.Bytes) != 44 {
		err := errors.New("unexpected key length! check key type or path")
		return nil, err
	}
	newKey := make([]byte, NoisePrivateKeySize)
	// 44 - 32 = 12
	copy(newKey, srcKey.Bytes[12:])
	return &newKey, nil
}

// Try to find a suitable key on the hsm for x25519 key derivation
// parameter GET_PUB_KEY sets the search pattern for a public or private key
func (dev *PKClient) findDeriveKey(GET_PUB_KEY bool) (key p11.Object, err error) {
	//  EC_PARAMS value: the specifc OID for x25519 operation
	rawOID, _ := hex.DecodeString(CURVE25519_OID_RAW)

	keyAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}
	var keyType *pkcs11.Attribute
	if GET_PUB_KEY {
		keyType = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY)
	} else {
		keyType = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)
	}
	keyAttrs = append(keyAttrs, keyType)

	key, err = dev.HSM_Session.session.FindObject(keyAttrs)
	if err != nil {
		return key, err
	}
	return key, nil
}

// Takes a raw wireguard pubkey and writes it to a PEM formatted file
// Probably not needed or very useful
func wgKeyToPem(pubKey *[]byte, IS_PUB_KEY bool) ([]byte, error) {
	buf, err := hex.DecodeString(PEM_PUB_HEADER)
	if err != nil {
		return nil, err
	}
	if IS_PUB_KEY {
		pemKey := make([]byte, PEM_PUB_KEY_SIZE)
		copy(pemKey[:11], buf)
		copy(pemKey[12:], *pubKey)
		return pemKey, nil

	} else { // private key
		pemKey := make([]byte, PEM_PRIV_KEY_SIZE)
		copy(pemKey[:15], buf)
		copy(pemKey[16:], *pubKey)
		return pemKey, nil
	}
}

// Some unused helper functions that may be handly later
// TODO move some of these to a utility helper function

//convert and write a PEM x25519 key to the 'WG format' (shorter, no header)
func writePemToRawKey(writePath string, key *[]byte) error {
	ss := base64.StdEncoding.EncodeToString(*key)
	ss += "\n"
	err := writeToFile(writePath, []byte(ss))
	if err != nil {
		return err
	}
	return nil

}

// loads a key file into a PEM ptr from the given path
func loadPemKeyFile(path string) (pemKey *pem.Block, err error) {
	keyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	fileInfo, _ := keyFile.Stat()
	size := fileInfo.Size()
	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(keyFile)
	_, err = buffer.Read(pemBytes)

	pemKey, _ = pem.Decode([]byte(pemBytes))

	return pemKey, err
}

// Loads a 'raw' base64 encoded key
func loadRawKey(path string) ([]byte, error) {
	rawKeyB64, err := ioutil.ReadFile(path)
	str := string(rawKeyB64)
	fmt.Printf("Key was: %s\n", rawKeyB64)

	rawKey, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return rawKey, nil

}

// create a PEM file
func writeKeyToPemFile(path string, data []byte, IS_PUB_KEY bool) error {
	var key_type string = "PUBLIC"
	if !IS_PUB_KEY {
		key_type = "PRIVATE"
	}

	// create the PEM strings
	var start string = "-----BEGIN " + key_type + " KEY-----\n"
	var end string = "-----END " + key_type + " KEY-----\n"
	var body string = string(data) + "\n"
	result := start + body + end

	err := writeToFile(path, []byte(result))
	if err != nil {
		return err
	}
	return nil
}

func writeToFile(path string, data []byte) error {
	//err := os.Create(path, data, 0644)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	file.Write(data)
	if err != nil {
		return err
	}
	return nil
}
