module github.com/neicnordic/crypt4gh

go 1.26.4

require (
	filippo.io/edwards25519 v1.2.0
	github.com/dchest/bcrypt_pbkdf v1.0.0
	github.com/hashicorp/go-version v1.9.0
	github.com/jessevdk/go-flags v1.6.1
	github.com/logrusorgru/aurora/v4 v4.0.0
	golang.org/x/crypto v0.53.0
	golang.org/x/term v0.44.0
)

require golang.org/x/sys v0.46.0 // indirect

retract v1.8.7 // has a bug related to file decryption that ends up in loop.
