package main

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

const PIN = "3537363231383830"
const PKCS11_LIB = "/usr/lib/pkcs11/opensc-pkcs11.so"

func main() {

	hw_key := setup_pkcs11()
	defer hw_key.Destroy()
	defer hw_key.Finalize()

	var tInfo, err = hw_key.GetTokenInfo(0)
	if err != nil {
		panic(err)
	}
	println("=======================")
	// Print the token informaiton (the generic hardware key details)
	fmt.Printf("%+v\n", tInfo)

	var mechInfo []*pkcs11.Mechanism
	mechInfo, err = hw_key.GetMechanismList(0)

	printMech(mechInfo)
	/* 	   	println("====other way ====")
	fmt.Printf("%+v\n", mechInfo)
	*/

	println("HW Key is at:", hw_key)

	slots, err := hw_key.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	// ... find the appropriate slot, then ...
	session, err := hw_key.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer hw_key.CloseSession(session)

	err = hw_key.Login(session, pkcs11.CKU_USER, PIN)
	if err != nil {
		panic(err)
	} else {
		println("We now have a session open...")
	}

	defer hw_key.Logout(session)

	// do something

	//mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_RSA_PKCS_PSS, params)}
	var KDF uint
	var SharedData []byte
	var PublicKeyData []byte
	//params := pkcs11.NewECDH1DeriveParams(uint(t.Ecdh1.Kdf), t.Ecdh1.SharedData, t.Ecdh1.PublicKeyData)
	params := pkcs11.NewECDH1DeriveParams(KDF, SharedData, PublicKeyData)

	//var mechPtr *pkcs11.Mechanism = req.getMyMech()
	ecdhmech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)}

	println(ecdhmech)

	priv, err := findKeys(hw_key, session)
	if err != nil {
		panic(err)
	}
	println("Got obj handle:", priv)
	for i := 0; i < len(priv); i++ {
		println("ID:", priv[i])
		println("Getting Attrrs")
		GetAttrs(hw_key, &session, &priv[i])
		println("Done")

	}
	tokenLabel := "Encryption key"
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // persistent
	}
	println(keyTemplate)
	fmt.Printf("%+v\n", priv)

	secret, err := hw_key.DeriveKey(session, ecdhmech, priv[1], keyTemplate)
	if err != nil {
		println("Error deriving key :(")
	}
	println("Secret value:", secret)
}

// setup the pkcs11 context helper and return a context
func setup_pkcs11() *pkcs11.Ctx {
	p := pkcs11.New(PKCS11_LIB)
	err := p.Initialize()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Library initiliazed successfully")
		return p
	}
}

// clean this up for error handling, this finds an object? We only want one, should we return just the first?
func findKeys(hw_key *pkcs11.Ctx, session pkcs11.SessionHandle) ([]pkcs11.ObjectHandle, error) {

	tokenLabel := "Encryption key"
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel)}

	// find the object handle for the derivation key
	err := hw_key.FindObjectsInit(session, template)
	if err != nil {
		panic(err)
	}
	obj, _, err := hw_key.FindObjects(session, 10)
	if err != nil {
		panic(err)
	}
	err = hw_key.FindObjectsFinal(session)
	if err != nil {
		panic(err)
	}
	if len(obj) == 0 {
		println("Coulnd't find a key with that label!")
		err = errors.New("Coulnd't find a key with that label!")
		return nil, err

	}
	println("Found ", len(obj), " objects")
	for i := range obj {
		fmt.Printf("Object Handle:%d\n", obj[i])
	}
	return obj, nil
}

type Mechy struct {
	mechanism *pkcs11.Mechanism
	slot      uint
}

func printMech(list []*pkcs11.Mechanism) {
	for i := range list {
		fmt.Printf("Mechanism: %x\n", list[i].Mechanism)
		fmt.Printf("Parameter:%x\n", list[i].Parameter)
	}
}

// Can't even get the object attrs correctly
func GetAttrs(hw_key *pkcs11.Ctx, session *pkcs11.SessionHandle, obj *pkcs11.ObjectHandle) {

	template := []*pkcs11.Attribute{
		//pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		//pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		//pkcs11.NewAttribute(pkcs11.CKA_TOKEN, nil),
	}
	attr, err := hw_key.GetAttributeValue(*session, pkcs11.ObjectHandle(*obj), template)
	if err != nil {
		println("Error getting attributes!")
	}
	println("attrs", attr)
	//for i, a := range attr {
	//fmt.Printf("attr %d, type %d, valuelen %d\n", i, a.Type, len(a.Value))

	//}
}

/* 	privateKeyObject, err := session.FindObject(...)
		if err != nil {
  			return err
		} */
// these are the same thing
/* 	x := 5
   	var y int = 6
   	var sum int = x + y
   	fmt.Println("Hello whrilled")

   	fmt.Println("Sum:", sum)

   	if x > y {
   		fmt.Println(x, " is bigger than ", y)

   	} else {

   		fmt.Println(y, " is larger than ", x)
   	}

   	for i := 0; i < 5; i++ {
   		fmt.Print(i)

   	}
   	fmt.Println()

   	fmt.Print(x, " plus one is ")
   	incre(&x)
   	fmt.Println(x) */

/* func getMyMech(mech *mech.Mechanism) *pkcs11.Mechanism {

	out := make([]*pkcs11.Mechanism, len(mechs))
	var params interface{}
	t := mech.GetData().(type)
	var newmech = pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)
	return newmech
} */

/* func (be *Pkcs11Backend) ecdhDeriveKey(derivedKeyID string, derivedKeyLen uint, privateKeyHandle pkcs11.ObjectHandle, peerPublicKey *ecdsa.PublicKey) (pkcs11.ObjectHandle, error) {
	point := elliptic.Marshal(peerPublicKey.Curve, peerPublicKey.X, peerPublicKey.Y)
	// According to PKCS#11, tokens that support CKM_ECDH1_DERIVE mechanism MUST accept
	// raw encoding (Sec. A.5.2 of ANSI X9.62) of public key for CKM_ECDH1_DERIVE mechanism,
	// and may optionally accept DER encoding.
	// we don't support DER encoding for now
	asn1Point, _ := asn1.Marshal(point)
	params, free := ecdh1DeriveParamBytes(asn1Point)
	defer free()
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)}
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, derivedKeyLen/8),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, derivedKeyID),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // persistent
	}
	key, err := be.ctx.DeriveKey(be.sessionHandle, mechanism, privateKeyHandle, keyTemplate)
	if err != nil {
		return invalidObjectHandle, errors.Wrapf(err, "Error deriving AES key using ECDH, base key handle: %v, derived key id: %v", privateKeyHandle, derivedKeyLen)
	}
	return key, nil
} */
