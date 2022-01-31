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

const PIN = "3537363231383830"
const PKCS11_LIB = "/usr/lib/pkcs11/opensc-pkcs11.so"

//const tokenLabel = "Encryption Key"
//const peerKeyPath = "../../certs/alice/alice_pub.pem"
const peerKeyPath = "../../certs/nitro/hw_key.pub"
const peerKeyWGOutPath = "../../certs/nitro/hw_key.wg"
const peerKeyWGPath = "../../certs/alice/test_wg_pub.pem"
const peerPrivKeyWGPath = "../../certs/alice/test_wg_priv.pem"
const peerRawWGKey = "../../certs/test_client/publickey"
const outputPath = "goSecret.bin"

const (
	PEM_PUB_HEADER      = "302a300506032b656e032100"
	PEM_PRIV_HEADER     = "302e020100300506032b656e04220420"
	PEM_PUB_KEY_SIZE    = 44
	PEM_PRIV_KEY_SIZE   = 48
	NoisePrivateKeySize = 32
	NoisePublicKeySize  = 32
)

type pkclient struct {
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

/* 	// load a pem key into a pem ptr
peerKeyPtr := loadPemKeyFile(peerKeyPath)
// get the raw key version from the pem ptr
rawKeyPtr, err := getRaw25519Key(peerKeyPtr)
if err != nil {
	fmt.Println(err)
	os.Exit(1)
}

// write a raw x25519 key to file in WG format
writePemToRawKey(peerKeyWGOutPath, rawKeyPtr)
// load a wireguard public key
rawWGPK, err := loadRawKey(peerRawWGKey)
//fmt.Printf("Raw WG KEY: %X\n", rawWGPK)
if err != nil {
	fmt.Println(err)
	os.Exit(1)
}|
*/

//convert the (rawkey back to PEM for learning
/* 	convertedPemKey, err := wgKeyToPem(rawKeyPtr, true)
   	if err != nil {
   		fmt.Println(err)
   		os.Exit(1)
   	} */

//fmt.Printf("converted key: %X\n", convertedPemKey)

/* 	encodedStr := base64.StdEncoding.EncodeToString(convertedPemKey)
   	fmt.Println("base64 encoded string:")
   	fmt.Println(encodedStr)
   	encodedByte := []byte(encodedStr) */
//writeKeyToPemFile(peerKeyWGPath, encodedByte, true)

// right now we don't support user input pins
// TODO add ability to have user enter their pin so we don't save it
// try to open a session with the HSM, select the slot and login to it.
// also try to find an x25519 key to derive with so we can fail early if
// if the program can't derive
func New(hsm_path string, requestedSlot uint, pin string) (*pkclient, error) {
	client := new(pkclient)

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
	client.HSM_Session.session, err = slots[requestedSlot].OpenWriteSession()
	if err != nil {
		err := fmt.Errorf("failed to open session on slot %d", requestedSlot)
		return nil, err
	}
	client.HSM_Session.slot = requestedSlot // we don't need to save this but maybe we could use it in the future?
	//client.HSM_Session.session = session
	// login to the slot
	err = client.HSM_Session.session.Login(pin)
	if err != nil {
		//fmt.Println("login error, bad pin?", err)
		return nil, err
	}
	//login successful
	client.HSM_Session.pin = pin

	// make sure this device has a private curve25519 key for deriving
	client.HSM_Session.PrivKeyObj, err = client.findDeriveKey(false)
	if err != nil {
		return nil, err
	}

	// lastly, make sure we can find the public key of the private key, so we can pass it to a requesting client
	// TODO improve the interface to pkclient so we don't have to have such deep references
	client.HSM_Session.PubKeyObj, err = client.findDeriveKey(true)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// helper function that will try to return
// and return the raw bytes for use by consumers which use raw keys, like WireGard
func (client *pkclient) PublicKey() ([]byte, error) {
	key, err := client.HSM_Session.PubKeyObj.Value()
	if err != nil {
		return nil, err
	}
	return key, nil
}

// helper function that will import a PEM formatted curve25519 public key
// and return the raw bytes for use by consumers which use raw keys, like WireGard
func PublicKeyFromFile(pemFilePath string) (key []byte, err error) {
	pemFile, err := loadPemKeyFile(pemFilePath)
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

// derives a secret key on a private key with the peerPubKey parameter
func (client *pkclient) Derive(peerPubKey []byte) ([]byte, error) {
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

//Loads a 'raw' base64 encoded key
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

// There must be a function somewhere that already does this.
// from my debugging of EVP_PKEY_get_raw_public_key:
// It seems to return the last 32 bytes of the 'key' when comparing
// the hex output from the 44 bytes that we get from rawKey
func getRaw25519Key(srcKey *pem.Block) (*[]byte, error) {
	if len(srcKey.Bytes) != 44 {
		err := errors.New("unexpected key length! check key type or path")
		return nil, err
	}
	newKey := make([]byte, NoisePrivateKeySize)
	// 44 - 32 = 12
	copy(newKey, srcKey.Bytes[12:])
	return &newKey, nil
}

// Attempts to return deriveKey, either the public or private version
// : parameter IS_PUB_KEY sets the search pattern for either a public or private key
func (dev *pkclient) findDeriveKey(IS_PUB_KEY bool) (key p11.Object, err error) {
	keyAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	if IS_PUB_KEY {
		// prebuilt private key attributes for finding the x25519 key on the HSM
		keyAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
	}

	key, err = dev.HSM_Session.session.FindObject(keyAttrs)
	if err != nil {
		return key, err
	}
	return key, nil
}

/* func saveThisForLater() {
	ss := base64.StdEncoding.EncodeToString(secret)
	fmt.Printf("Success! Derived secret: \n%s\n", ss)

	err = writeToFile(outputPath, secret)
	if err != nil {
		fmt.Printf("Error writing to file: %s\n", err)
	}
 	label, _ := privateKeyObject.Label()
	   	fmt.Printf("Label:%s\n", label)
	   	fmt.Printf("Found private key! %s\n", privateKeyObject)
	return nil
}
*/

func getMechList(slots []p11.Slot) {

	mechlist, err := slots[0].Mechanisms()
	if err == nil {
		for i := range mechlist {
			mechInfo, err := mechlist[i].Info()
			if err == nil {
				fmt.Printf("mechs: ", mechInfo)
				println()
			}

		}
	}
}

func wgKeyToPem(pubKey *[]byte, IS_PUB_KEY bool) ([]byte, error) {
	buf, err := hex.DecodeString(PEM_PUB_HEADER)
	if err != nil {
		return nil, err
	}
	//var pemKey *[]byte
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
