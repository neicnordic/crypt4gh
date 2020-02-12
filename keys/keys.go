package keys

import (
	"encoding/pem"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"io"
	"io/ioutil"
	"maze.io/x/crypto/x25519"
)
import "golang.org/x/crypto/blake2b"

func ReadX25519PrivateKey(reader io.Reader) (*[chacha20poly1305.KeySize]byte, error) {
	pemBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	var key [chacha20poly1305.KeySize]byte
	copy(key[:], block.Bytes[len(block.Bytes)-x25519.GroupElementLength:])
	return &key, nil
}

func DerivePublicKey(privateKey [chacha20poly1305.KeySize]byte) [chacha20poly1305.KeySize]byte {
	var derivedPublicKey [chacha20poly1305.KeySize]byte
	curve25519.ScalarBaseMult(&derivedPublicKey, &privateKey)
	return derivedPublicKey
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
