package pkclient

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

const (
	PEM_PUB_HEADER      = "302a300506032b656e032100"
	PEM_PRIV_HEADER     = "302e020100300506032b656e04220420"
	CURVE25519_OID_RAW  = "06032B656E"
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

// TODO add ability to have user enter their pin so we don't save it

// Try to open a session with the HSM, select the slot and login to it
// A public and private key must already exist on the hsm and be found during
// setup. The private key must be the Curve25519 Algorithm, OID 1.3.101.110
//
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

// derive a shared secret using the input public key against the private key that was found during setup
// returns a fixed 32 byte array
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
