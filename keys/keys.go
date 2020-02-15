package keys

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
)
import "golang.org/x/crypto/blake2b"

const (
	ed25519Algorithm = "1.3.101.112"
	x25519Algorithm  = "1.3.101.110"
)

func GenerateKeyPair() (publicKey [chacha20poly1305.KeySize]byte, privateKey [chacha20poly1305.KeySize]byte, err error) {
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return
	}

	var edPublicKeyBytes [chacha20poly1305.KeySize]byte
	copy(edPublicKeyBytes[:], edPublicKey)
	extra25519.PublicKeyToCurve25519(&publicKey, &edPublicKeyBytes)

	var edPrivateKeyBytes [chacha20poly1305.KeySize * 2]byte
	copy(edPrivateKeyBytes[:], edPrivateKey)
	extra25519.PrivateKeyToCurve25519(&privateKey, &edPrivateKeyBytes)

	return
}

type openSSLPrivateKey struct {
	Version   int
	Algorithm pkix.AlgorithmIdentifier
}

func ReadPrivateKey(reader io.Reader, passPhrase []byte) (privateKey [chacha20poly1305.KeySize]byte, err error) {
	var allBytes []byte
	allBytes, err = ioutil.ReadAll(reader)
	if err != nil {
		return
	}

	// Trying to read OpenSSH Ed25519 private key
	var key interface{}
	if passPhrase == nil {
		key, err = ssh.ParseRawPrivateKey(allBytes)
	} else {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(allBytes, passPhrase)
	}
	if err == nil {
		edPrivateKey := key.(*ed25519.PrivateKey)
		var edKeyBytes [chacha20poly1305.KeySize * 2]byte
		copy(edKeyBytes[:], *edPrivateKey)
		extra25519.PrivateKeyToCurve25519(&privateKey, &edKeyBytes)
		return
	}

	// Not OpenSSH private key, assuming OpenSSL private key, trying to figure out type (Ed25519 or X25519)
	block, _ := pem.Decode(allBytes)

	var openSSLPrivateKey openSSLPrivateKey
	if _, err = asn1.Unmarshal(block.Bytes, &openSSLPrivateKey); err != nil {
		return
	}

	// Trying to read OpenSSL Ed25519 private key and convert to X25519 private key
	if openSSLPrivateKey.Algorithm.Algorithm.String() == ed25519Algorithm {
		var edKeyBytes [chacha20poly1305.KeySize * 2]byte
		copy(edKeyBytes[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
		extra25519.PrivateKeyToCurve25519(&privateKey, &edKeyBytes)
		return
	}

	// Trying to read OpenSSL X25519 private key
	if openSSLPrivateKey.Algorithm.Algorithm.String() == x25519Algorithm {
		copy(privateKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
		return
	}

	return privateKey, errors.New("private key format not supported")
}

type openSSLPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
}

func ReadPublicKey(reader io.Reader) (publicKey [chacha20poly1305.KeySize]byte, err error) {
	var allBytes []byte
	allBytes, err = ioutil.ReadAll(reader)
	if err != nil {
		return
	}

	// Trying to read OpenSSH Ed25519 public key
	key, _, _, _, err := ssh.ParseAuthorizedKey(allBytes)
	if err == nil {
		marshalledKey := key.Marshal()
		var edKeyBytes [chacha20poly1305.KeySize]byte
		copy(edKeyBytes[:], marshalledKey[len(marshalledKey)-chacha20poly1305.KeySize:])
		extra25519.PublicKeyToCurve25519(&publicKey, &edKeyBytes)
		return
	}

	// Not OpenSSH public key, assuming OpenSSL public key
	block, _ := pem.Decode(allBytes)
	var openSSLPublicKey openSSLPublicKey
	if _, err = asn1.Unmarshal(block.Bytes, &openSSLPublicKey); err != nil {
		return
	}

	// Trying to read OpenSSL Ed25519 public key and convert to X25519 public key
	if openSSLPublicKey.Algorithm.Algorithm.String() == ed25519Algorithm {
		var edKeyBytes [chacha20poly1305.KeySize]byte
		copy(edKeyBytes[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
		extra25519.PublicKeyToCurve25519(&publicKey, &edKeyBytes)
		return
	}

	// Trying to read OpenSSL X25519 public key
	if openSSLPublicKey.Algorithm.Algorithm.String() == x25519Algorithm {
		copy(publicKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
		return
	}

	return publicKey, errors.New("public key format not supported")
}

func DerivePublicKey(privateKey [chacha20poly1305.KeySize]byte) (publicKey [chacha20poly1305.KeySize]byte) {
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

func GenerateReaderSharedKey(privateKey [chacha20poly1305.KeySize]byte, publicKey [chacha20poly1305.KeySize]byte) (*[]byte, error) {
	derivedPublicKey := DerivePublicKey(privateKey)
	diffieHellmanKey, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}
	return generateSharedKey(diffieHellmanKey, derivedPublicKey, publicKey)
}

func GenerateWriterSharedKey(privateKey [chacha20poly1305.KeySize]byte, publicKey [chacha20poly1305.KeySize]byte) (*[]byte, error) {
	derivedPublicKey := DerivePublicKey(privateKey)
	diffieHellmanKey, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}
	return generateSharedKey(diffieHellmanKey, publicKey, derivedPublicKey)
}

func generateSharedKey(diffieHellmanKey []byte, readerPublicKey [chacha20poly1305.KeySize]byte, writerPublicKey [chacha20poly1305.KeySize]byte) (*[]byte, error) {
	combination := append(diffieHellmanKey, readerPublicKey[:]...)
	combination = append(combination, writerPublicKey[:]...)
	hash := blake2b.Sum512(combination)
	sharedKey := hash[:chacha20poly1305.KeySize]
	return &sharedKey, nil
}
