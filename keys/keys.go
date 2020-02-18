package keys

import (
	"bytes"
	"crypto/cipher"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
)
import "golang.org/x/crypto/blake2b"
import "github.com/elixir-oslo/crypt4gh/kdf"

const (
	privateKeyHeader    = "PRIVATE KEY"
	publicKeyHeader     = "PUBLIC KEY"
	magic               = "c4gh-v1"
	none                = "none"
	supportedCipherName = "chacha20_poly1305"
)

var ed25519Algorithm = []int{1, 3, 101, 112}
var x25519Algorithm = []int{1, 3, 101, 110}

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
	Payload   []byte
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
		// Sometimes the key is returned as a pointer, but sometimes as a value
		if edPrivateKey, ok := key.(*ed25519.PrivateKey); ok {
			var edKeyBytes [chacha20poly1305.KeySize * 2]byte
			copy(edKeyBytes[:], *edPrivateKey)
			extra25519.PrivateKeyToCurve25519(&privateKey, &edKeyBytes)
			return
		}
		edPrivateKey := key.(ed25519.PrivateKey)
		var edKeyBytes [chacha20poly1305.KeySize * 2]byte
		copy(edKeyBytes[:], edPrivateKey)
		extra25519.PrivateKeyToCurve25519(&privateKey, &edKeyBytes)
		return
	}

	// Not OpenSSH private key, assuming OpenSSL private key, trying to figure out type (Ed25519 or X25519)
	block, _ := pem.Decode(allBytes)

	var openSSLPrivateKey openSSLPrivateKey
	if _, err = asn1.Unmarshal(block.Bytes, &openSSLPrivateKey); err == nil {
		// Trying to read OpenSSL Ed25519 private key and convert to X25519 private key
		if openSSLPrivateKey.Algorithm.Algorithm.Equal(ed25519Algorithm) {
			var edKeyBytes [chacha20poly1305.KeySize * 2]byte
			copy(edKeyBytes[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
			extra25519.PrivateKeyToCurve25519(&privateKey, &edKeyBytes)
			return
		}

		// Trying to read OpenSSL X25519 private key
		if openSSLPrivateKey.Algorithm.Algorithm.Equal(x25519Algorithm) {
			copy(privateKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
			return
		}
	}

	// Interpreting bytes as Crypt4GH private key bytes (https://crypt4gh.readthedocs.io/en/latest/keys.html)
	if string(block.Bytes[:7]) == magic {
		return readCrypt4GHPrivateKey(block.Bytes, passPhrase)
	}

	return privateKey, errors.New("private key format not supported")
}

func readCrypt4GHPrivateKey(pemBytes []byte, passPhrase []byte) (privateKey [chacha20poly1305.KeySize]byte, err error) {
	buf := bytes.Buffer{}
	buf.Write(pemBytes[len(magic):])
	var length uint16
	err = binary.Read(&buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	kdfName := make([]byte, length)
	err = binary.Read(&buf, binary.BigEndian, &kdfName)
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
		err = binary.Read(&buf, binary.BigEndian, &length)
		if err != nil {
			return
		}
		err = binary.Read(&buf, binary.BigEndian, &rounds)
		if err != nil {
			return
		}
		salt = make([]byte, length-4)
		err = binary.Read(&buf, binary.BigEndian, &salt)
		if err != nil {
			return
		}
	}
	err = binary.Read(&buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	ciphername := make([]byte, length)
	err = binary.Read(&buf, binary.BigEndian, &ciphername)
	if err != nil {
		return
	}
	err = binary.Read(&buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	payload := make([]byte, length)
	err = binary.Read(&buf, binary.BigEndian, &payload)
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
	if _, err = asn1.Unmarshal(block.Bytes, &openSSLPublicKey); err == nil {
		// Trying to read OpenSSL Ed25519 public key and convert to X25519 public key
		if openSSLPublicKey.Algorithm.Algorithm.Equal(ed25519Algorithm) {
			var edKeyBytes [chacha20poly1305.KeySize]byte
			copy(edKeyBytes[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
			extra25519.PublicKeyToCurve25519(&publicKey, &edKeyBytes)
			return
		}
		// Trying to read OpenSSL X25519 public key
		if openSSLPublicKey.Algorithm.Algorithm.Equal(x25519Algorithm) {
			copy(publicKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
			return
		}
	}

	// Interpreting bytes as Crypt4GH public key bytes (X25519)
	copy(publicKey[:], block.Bytes[len(block.Bytes)-chacha20poly1305.KeySize:])
	return publicKey, nil
}

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
		Type:    privateKeyHeader,
		Headers: nil,
		Bytes:   marshalledPrivateKey,
	}
	return pem.Encode(writer, &block)
}

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
		Type:    publicKeyHeader,
		Headers: nil,
		Bytes:   marshalledPublicKey,
	}
	return pem.Encode(writer, &block)
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
