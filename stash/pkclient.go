package main

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

const PIN = "3537363231383830"
const PKCS11_LIB = "/usr/lib/pkcs11/opensc-pkcs11.so"

func main() {

	hw_key := setup_pkcs11()
	defer hw_key.Destroy()
	defer hw_key.Finalize()

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
	var newmech = pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)
	println(newmech)

	tokenLabel := "derivedKey"

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // persistent
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
}

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

// setup the pkcs11 context helper and return a context
func setup_pkcs11() *pkcs11.Ctx {
	/* 	fileinfo, err := os.Stat(PKCS11_LIB)
	   	if os.IsNotExist(err) {
	   		log.Fatal("Fatal: file:", PKCS11_LIB, " does not exist.")
	   		log.Println(fileinfo)
	   	} */
	p := pkcs11.New(PKCS11_LIB)
	err := p.Initialize()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Library initiliazed successfully")
		return p
	}
}
