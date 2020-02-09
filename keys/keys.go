package keys

import "crypto/rand"
import "maze.io/x/crypto/x25519"

type KeyPair struct {
	PublicKey  x25519.PublicKey
	PrivateKey x25519.PrivateKey
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{PublicKey: privateKey.PublicKey, PrivateKey: *privateKey}, nil
}
