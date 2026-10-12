module github.com/neicnordic/crypt4gh

go 1.27.1

require (
	filippo.io/edwards25519 v1.2.0
	github.com/dchest/bcrypt_pbkdf v1.0.0
	github.com/hashicorp/go-version v1.9.0
	github.com/jessevdk/go-flags v1.6.1
	github.com/logrusorgru/aurora/v4 v4.0.0
	golang.org/x/crypto v0.58.0
	golang.org/x/term v0.47.0
)

require golang.org/x/sys v0.49.0 // indirect

retract (
	v1.15.1 // wrong tag, should have been 1.16.0
	v1.8.7 // has a bug related to file decryption that ends up in loop.
)
