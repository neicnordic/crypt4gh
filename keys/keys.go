// Package keys holds helper methods to generate/read/convert/write keys for Crypt4GH.
// Supported keys: OpenSSH (Ed25519), OpenSSL (Ed25519, X25519), Crypt4GH (X25519).
package keys

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"crypto/sha512"

	"filippo.io/edwards25519"

	"github.com/neicnordic/crypt4gh/kdf"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const (
	openSSLPrivateKeyHeader  = "PRIVATE KEY"
	openSSLPublicKeyHeader   = "PUBLIC KEY"
	crypt4GHPrivateKeyHeader = "CRYPT4GH ENCRYPTED PRIVATE KEY"
	crypt4GHPublicKeyHeader  = "CRYPT4GH PUBLIC KEY"
	magic                    = "c4gh-v1"
	none                     = "none"
	supportedCipherName      = "chacha20_poly1305"
)

var ed25519Algorithm = []int{1, 3, 101, 112}
var x25519Algorithm = []int{1, 3, 101, 110}

// GenerateKeyPair method generates X25519 key pair.
func GenerateKeyPair() (publicKey, privateKey [chacha20poly1305.KeySize]byte, err error) {
	edCurve, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	privateKey = [32]byte(edCurve.Bytes())

	publicKey = [32]byte(edCurve.PublicKey().Bytes())

	return
}

type openSSLPrivateKey struct {
	Version   int
	Algorithm pkix.AlgorithmIdentifier
	Payload   []byte
}

// ReadPrivateKey reads private key from io.Reader.
// Supported keys: OpenSSH (Ed25519, ECDH X25519), OpenSSL (Ed25519, X25519), Crypt4GH (X25519).
func ReadPrivateKey(reader io.Reader, passPhrase []byte) (privateKey [chacha20poly1305.KeySize]byte, err error) {
	var allBytes []byte
	allBytes, err = io.ReadAll(reader)
	if err != nil {
		return
	}

	// Trying to read OpenSSH Ed25519 and ECDH X25519 private keys
	var key interface{}
	if passPhrase == nil {
		key, err = ssh.ParseRawPrivateKey(allBytes)
	} else {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(allBytes, passPhrase)
	}
	if err == nil {
		// Sometimes the key is returned as a pointer, but sometimes as a value

		switch v := key.(type) {
		case ed25519.PrivateKey:
			PrivateKeyToCurve25519(&privateKey, v)
		case *ed25519.PrivateKey:
			PrivateKeyToCurve25519(&privateKey, *v)
		case ecdh.PrivateKey:
			privateKey = [32]byte(v.Bytes())
		case *ecdh.PrivateKey:
			privateKey = [32]byte(v.Bytes())
		}

		return
	}

	block, _ := pem.Decode(allBytes)

	if block == nil {
		return [chacha20poly1305.KeySize]byte{}, fmt.Errorf("read of unrecognized private key format failed; " +
			"expected PEM encoded key")
	}

	// Interpreting bytes as Crypt4GH private key bytes (https://crypt4gh.readthedocs.io/en/latest/keys.html)
	if len(block.Bytes) > 8 && string(block.Bytes[:7]) == magic {
		return readCrypt4GHPrivateKey(block.Bytes, passPhrase)
	}

	return privateKey, errors.New("private key format not supported")
}

func readCrypt4GHPrivateKey(pemBytes, passPhrase []byte) (privateKey [chacha20poly1305.KeySize]byte, err error) {
	buffer := bytes.NewBuffer(pemBytes[len(magic):])
	var length uint16
	err = binary.Read(buffer, binary.BigEndian, &length)
	if err != nil {
		return
	}
	kdfName := make([]byte, length)
	err = binary.Read(buffer, binary.BigEndian, &kdfName)
	if err != nil {
		return
	}
	var rounds uint32
	var salt []byte
	kdfunction, ok := kdf.KDFS[string(kdfName)]
	if !ok {
		return privateKey, fmt.Errorf("KDF %v not supported", string(kdfName))
	}
	if string(kdfName) != "none" {
		if passPhrase == nil {
			return privateKey, errors.New("private key is password-protected, need a password for decryption")
		}
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			return
		}
		err = binary.Read(buffer, binary.BigEndian, &rounds)
		if err != nil {
			return
		}
		salt = make([]byte, length-4)
		err = binary.Read(buffer, binary.BigEndian, &salt)
		if err != nil {
			return
		}
	}
	err = binary.Read(buffer, binary.BigEndian, &length)
	if err != nil {
		return
	}
	ciphername := make([]byte, length)
	err = binary.Read(buffer, binary.BigEndian, &ciphername)
	if err != nil {
		return
	}
	err = binary.Read(buffer, binary.BigEndian, &length)
	if err != nil {
		return
	}
	payload := make([]byte, length)
	err = binary.Read(buffer, binary.BigEndian, &payload)
	if err != nil {
		return
	}
	if string(kdfName) == none {
		if string(ciphername) != none {
			return privateKey, errors.New("invalid private key: KDF is 'none', but cipher is not 'none'")
		}
		copy(privateKey[:], payload)

		return
	}
	if string(ciphername) != supportedCipherName {
		return privateKey, fmt.Errorf("unsupported key encryption: %v", string(ciphername))
	}
	var derivedKey []byte
	derivedKey, err = kdfunction.Derive(int(rounds), passPhrase, salt)
	if err != nil {
		return
	}
	var aead cipher.AEAD
	aead, err = chacha20poly1305.New(derivedKey)
	if err != nil {
		return
	}
	var decryptedPrivateKey []byte
	decryptedPrivateKey, err = aead.Open(nil, payload[:chacha20poly1305.NonceSize], payload[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return privateKey, err
	}
	copy(privateKey[:], decryptedPrivateKey)

	return
}

type openSSLPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	Payload   asn1.BitString
}

// ReadPublicKey reads public key from io.Reader.
// Supported keys: OpenSSH (Ed25519), OpenSSL (Ed25519, X25519), Crypt4GH (X25519).
func ReadPublicKey(reader io.Reader) (publicKey [chacha20poly1305.KeySize]byte, err error) {
	var allBytes []byte
	allBytes, err = io.ReadAll(reader)
	if err != nil {
		return
	}

	// Trying to read OpenSSH Ed25519 public key
	key, _, _, _, err := ssh.ParseAuthorizedKey(allBytes)
	if err == nil {
		marshalledKey := key.Marshal()
		var edKeyBytes ed25519.PublicKey = marshalledKey[len(marshalledKey)-chacha20poly1305.KeySize:]
		PublicKeyToCurve25519(&publicKey, edKeyBytes)

		return
	}

	// Not OpenSSH public key, assuming OpenSSL public key
	block, _ := pem.Decode(allBytes)

	if block == nil {
		return [chacha20poly1305.KeySize]byte{}, fmt.Errorf("Read of unrecognized public key format failed; " +
			"expected PEM encoded key")
	}

	var openSSLPublicKey openSSLPublicKey
	if _, err = asn1.Unmarshal(block.Bytes, &openSSLPublicKey); err == nil {
		// Trying to read OpenSSL Ed25519 public key and convert to X25519 public key
		if openSSLPublicKey.Algorithm.Algorithm.Equal(ed25519Algorithm) {
			var edKeyBytes ed25519.PublicKey = block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:]
			PublicKeyToCurve25519(&publicKey, edKeyBytes)

			return
		}
		// Trying to read OpenSSL X25519 public key
		if openSSLPublicKey.Algorithm.Algorithm.Equal(x25519Algorithm) {
			copy(publicKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])

			return
		}
	}

	if len(block.Bytes) < chacha20poly1305.KeySize {
		return publicKey, fmt.Errorf("Unsupported key file format")
	}
	// Interpreting bytes as Crypt4GH public key bytes (X25519)
	copy(publicKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])

	return publicKey, nil
}

// WriteOpenSSLX25519PrivateKey writes X25519 public key to io.Writer in OpenSSL format.
func WriteOpenSSLX25519PrivateKey(writer io.Writer, privateKey [chacha20poly1305.KeySize]byte) error {
	marshalledPayload, err := asn1.Marshal(privateKey[:])
	if err != nil {
		return err
	}
	openSSLPrivateKey := openSSLPrivateKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: x25519Algorithm},
		Payload:   marshalledPayload,
	}
	marshalledPrivateKey, err := asn1.Marshal(openSSLPrivateKey)
	if err != nil {
		return err
	}
	block := pem.Block{
		Type:    openSSLPrivateKeyHeader,
		Headers: nil,
		Bytes:   marshalledPrivateKey,
	}

	return pem.Encode(writer, &block)
}

// WriteOpenSSLX25519PublicKey writes X25519 public key to io.Writer in OpenSSL format.
func WriteOpenSSLX25519PublicKey(writer io.Writer, publicKey [chacha20poly1305.KeySize]byte) error {
	openSSLPrivateKey := openSSLPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: x25519Algorithm},
		Payload:   asn1.BitString{Bytes: publicKey[:]},
	}
	marshalledPublicKey, err := asn1.Marshal(openSSLPrivateKey)
	if err != nil {
		return err
	}
	block := pem.Block{
		Type:    openSSLPublicKeyHeader,
		Headers: nil,
		Bytes:   marshalledPublicKey,
	}

	return pem.Encode(writer, &block)
}

// WriteCrypt4GHX25519PrivateKey writes X25519 public key to io.Writer in Crypt4GH format.
func WriteCrypt4GHX25519PrivateKey(writer io.Writer, privateKey [chacha20poly1305.KeySize]byte, password []byte) error {
	kdfName := "scrypt"

	salt := [16]byte{}
	_, err := rand.Reader.Read(salt[:])
	if err != nil {
		return err
	}
	derivedKey, err := kdf.KDFS[kdfName].Derive(0, password, salt[:])
	if err != nil {
		return err
	}

	nonce := [chacha20poly1305.NonceSize]byte{}
	_, err = rand.Reader.Read(nonce[:])
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return err
	}
	encryptedPrivateKey := aead.Seal(nil, nonce[:], privateKey[:], nil)

	buffer := bytes.NewBuffer([]byte(magic))
	length := uint16(len(kdfName))
	err = binary.Write(buffer, binary.BigEndian, length)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.BigEndian, []byte(kdfName))
	if err != nil {
		return err
	}
	rounds := [4]byte{}
	roundsWithSalt := append(rounds[:], salt[:]...)
	length = uint16(len(roundsWithSalt))
	err = binary.Write(buffer, binary.BigEndian, length)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.BigEndian, roundsWithSalt)
	if err != nil {
		return err
	}
	length = uint16(len(supportedCipherName))
	err = binary.Write(buffer, binary.BigEndian, length)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.BigEndian, []byte(supportedCipherName))
	if err != nil {
		return err
	}
	nonceWithKey := append(nonce[:], encryptedPrivateKey...)
	length = uint16(len(nonceWithKey))
	err = binary.Write(buffer, binary.BigEndian, length)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.BigEndian, nonceWithKey)
	if err != nil {
		return err
	}

	block := pem.Block{
		Type:    crypt4GHPrivateKeyHeader,
		Headers: nil,
		Bytes:   buffer.Bytes(),
	}

	return pem.Encode(writer, &block)
}

// WriteCrypt4GHX25519PublicKey writes X25519 public key to io.Writer in Crypt4GH format.
func WriteCrypt4GHX25519PublicKey(writer io.Writer, publicKey [chacha20poly1305.KeySize]byte) error {
	block := pem.Block{
		Type:    crypt4GHPublicKeyHeader,
		Headers: nil,
		Bytes:   publicKey[:],
	}

	return pem.Encode(writer, &block)
}

// DerivePublicKey derives public key from X25519 private key.
func DerivePublicKey(privateKey [chacha20poly1305.KeySize]byte) (publicKey [chacha20poly1305.KeySize]byte) {
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return
}

// GenerateReaderSharedKey generates shared key for recipient, based on ECDH and BLAKE2 SHA-512.
func GenerateReaderSharedKey(privateKey, publicKey [chacha20poly1305.KeySize]byte) (*[]byte, error) {
	derivedPublicKey := DerivePublicKey(privateKey)
	diffieHellmanKey, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}

	return generateSharedKey(diffieHellmanKey, derivedPublicKey, publicKey)
}

// GenerateWriterSharedKey generates shared key for sender, based on ECDH and BLAKE2 SHA-512.
func GenerateWriterSharedKey(privateKey, publicKey [chacha20poly1305.KeySize]byte) (*[]byte, error) {
	derivedPublicKey := DerivePublicKey(privateKey)
	diffieHellmanKey, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}

	return generateSharedKey(diffieHellmanKey, publicKey, derivedPublicKey)
}

func generateSharedKey(diffieHellmanKey []byte, readerPublicKey [32]byte, writerPublicKey [chacha20poly1305.KeySize]byte) (*[]byte, error) {
	diffieHellmanKey = append(diffieHellmanKey, readerPublicKey[:]...)
	diffieHellmanKey = append(diffieHellmanKey, writerPublicKey[:]...)
	hash := blake2b.Sum512(diffieHellmanKey)
	sharedKey := hash[:chacha20poly1305.KeySize]

	return &sharedKey, nil
}

// functions below adapted from:
// https://github.com/cryptoscope/secretstream/blob/master/secrethandshake/internal/extra25519/convert.go

// PrivateKeyToCurve25519 converts an ed25519 private key into a corresponding
// curve25519 private key such that the resulting curve25519 public key will
// equal the result from PublicKeyToCurve25519.
func PrivateKeyToCurve25519(curve25519Private *[32]byte, privateKey ed25519.PrivateKey) {
	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	copy(curve25519Private[:], digest)
}

// PublicKeyToCurve25519 converts an Ed25519 public key into the curve25519
// public key that would be generated from the same private key.
func PublicKeyToCurve25519(curveBytes *[32]byte, edBytes ed25519.PublicKey) bool {

	edPoint, err := (&edwards25519.Point{}).SetBytes(edBytes)
	if err != nil {
		return false
	}

	copy(curveBytes[:], edPoint.BytesMontgomery())

	return true
}
