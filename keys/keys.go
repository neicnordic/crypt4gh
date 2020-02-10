package keys

import "golang.org/x/crypto/curve25519"
import "golang.org/x/crypto/blake2b"

func GenerateReaderSharedKey(privateKey [32]byte, publicKey [32]byte) (*[]byte, error) {
	derivedPublicKey := derivePublicKey(privateKey)
	diffieHellmanKey, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}
	return generateSharedKey(diffieHellmanKey, derivedPublicKey, publicKey)
}

func GenerateWriterSharedKey(privateKey [32]byte, publicKey [32]byte) (*[]byte, error) {
	derivedPublicKey := derivePublicKey(privateKey)
	diffieHellmanKey, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}
	return generateSharedKey(diffieHellmanKey, publicKey, derivedPublicKey)
}

func derivePublicKey(privateKey [32]byte) [32]byte {
	var derivedPublicKey [32]byte
	curve25519.ScalarBaseMult(&derivedPublicKey, &privateKey)
	return derivedPublicKey
}

func generateSharedKey(diffieHellmanKey []byte, readerPublicKey [32]byte, writerPublicKey [32]byte) (*[]byte, error) {
	combination := append(diffieHellmanKey, readerPublicKey[:]...)
	combination = append(combination, writerPublicKey[:]...)
	hash := blake2b.Sum512(combination)
	sharedKey := hash[:32]
	return &sharedKey, nil
}
