// Package kdf incorporates three KDFs (https://en.wikipedia.org/wiki/Key_derivation_function) used by Crypt4GH
package kdf

import (
	"crypto/sha256"

	// package is old but corresponds to "golang.org/x/crypto/ssh/internal/bcrypt_pbkdf"
	"github.com/dchest/bcrypt_pbkdf"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// KDFS is a map of KDF names to implementations.
var KDFS = map[string]KDF{
	"scrypt":             sCrypt{},
	"bcrypt":             bCrypt{},
	"pbkdf2_hmac_sha256": pbkdf2sha256{},
}

// KDF interface holding "Derive" method.
type KDF interface {
	Derive(rounds int, password []byte, salt []byte) (derivedKey []byte, err error)
}

type sCrypt struct {
}

func (sCrypt) Derive(_ int, password, salt []byte) (derivedKey []byte, err error) {
	return scrypt.Key(password, salt, 1<<14, 8, 1, chacha20poly1305.KeySize)
}

type bCrypt struct {
}

func (bCrypt) Derive(rounds int, password, salt []byte) (derivedKey []byte, err error) {
	return bcrypt_pbkdf.Key(password, salt, rounds, chacha20poly1305.KeySize)
}

type pbkdf2sha256 struct {
}

func (pbkdf2sha256) Derive(rounds int, password, salt []byte) (derivedKey []byte, err error) {
	return pbkdf2.Key(password, salt, rounds, chacha20poly1305.KeySize, sha256.New), nil
}
