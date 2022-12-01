# pkclient

This is a pkcs11 client for use with security keys/HSMs that support the ECDH x25519 key exchange algorithm

This client was written to explore WireGuard's ability to integrate hardware-support for it's underlying x25519 "sharedSecret" function.

This project has been successful and WireGuard sessions have been opened with non-modified clients.


## Background

This client has only been tested so far with the Nitrokey Start, since this project began in mid-summer 2021, the Nitrokey Start was one of the only usb security keys that supported ECDH x25519

Integrating this Golang-based client into the WireGuard VPN required some changes which have been published here: [Wireguard-goHSM](https://github.com/garnoth/wireguard-goHSM)

A fork for WireGuard-tools was also created so WireGuard-goHSM can load the HSM configuration options from the config client. [WireGuard-tools](https://github.com/garnoth/wireguard-tools)

## Configuration

After importing the go module, callers need to

This project currently requires functions from the current branch of https://github.com/miekg/pkcs11
Until a new release is made that includes the p11/Derive function, users will need to clone the repro and point pkclient at it using a replace command inside go.mod
The current go.mod expects the folder 'pkcs11' to be up one level from the pkclient directory. 

This project has only been tested using OpenSC's version of the pkcs11.so library on Linux and MacOS 

### WireGuard-goHSM
Instead of saving a PrivateKey in the [Interface] section of the config file, the configuration options has been modified:

	HSM = {pkcs11_library_path}, {slot_number}

Example:

	[Interface]
	HSM = /usr/lib/pkcs11/opensc-pkcs11.so, 0

A prompt will ask the user to enter the password once WireGuard-HSM reads the configuration and loads pkclient.
*Currently* this prompt is only on the command-line and isn't an operating system dialog. That would be a nice addition

## Setting up the Nitrokey Start
The process for getting a Curve25519 derivation key on the Nitrokey Start is as follows:

-Use GPG in advanced mode to generate x25519 keys on the card

	$ gpg --expert --full-gen-key 
	(-select the option for ECC)
	(-select 'Curve 25519' for the curve, probably option 1.)
	(-finish the rest of the options)

-Optionally use OpenSC's pkcs11-tool to verify the key exists on the card and can be seen via pkcs11
If you have OpenSC installed, you can verify that the correct type of key exists on the card:

	$ pkcs11-tool -O

You should see a Public Key Object like this:
	Public Key Object; EC_MONTGOMERY  EC_POINT 255 bits 

Now the pkclient should be able to locate the private and public when asked by WireGuard.

## Retriving the Curve25519 Public key
WireGuard-HSM will print the public key found on the HSM on start-up but you can also load the pkclient module manually and call the function
(it's work in progress to add a commandline option to dump this key)

Public keys for curve25519 are a little different, WireGuard represents them as pure 32 byte base64-encoded strings. 
OpenSSL and the pkcs11-tool will save them in PEM format which has a short ASN.1 header before the actual key. WireGuard doesn't know what to do with the header if it gets it.

### Automated method
Run WireGuard-goHSM and use the 'wg' tool to configure the interface with the HSM, it will dump the public key from the HSM to the command-line
	 ./wireguard-go -f wg0
	 /path/to/modified/wireguard-tools/wg setconf wg0 /path/to/wireguard_config_with_hsm.conf

Example Output: 

	HSM loaded, found public key: vEBA0KRvDcdOZg/abqnxlgYYMA7J6kh7saWSQParlBg=

### Manual Method
If you extract the public key using opensc, currently only the pkcs15-tool knows how to read curve25519 from hsms. Use the pkcs11-tool or pkcs15-tool to find the id number of the curve25519 key. The public and private key will have the same id. After generating the keys with gpg, mine was 02
pkcs15-tool --read-public-key 02 -o wg-pub.pem

TODO describe using pkclient to load and display the wg-pub.pem file
