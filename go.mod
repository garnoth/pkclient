module github.com/garnoth/pkclient

go 1.17

require (
	github.com/miekg/pkcs11 v1.1.1
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
)

require golang.org/x/sys v0.0.0-20220204135822-1c1b9b1eba6a // indirect

replace github.com/miekg/pkcs11 => ../../pkcs11
