package keys

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	derivedPublicKey := DerivePublicKey(privateKey)
	if bytes.Compare(publicKey[:], derivedPublicKey[:]) != 0 {
		t.Fail()
	}
}

func TestReadOpenSSHEd25519PrivateKeyUnencrypted(t *testing.T) {
	keyFile, err := os.Open("../test/ssh-ed25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(privateKey[:]) != "384757a869e462b447543b33f251abc2b2d833da131c71fefe162c6f8c3e1640" {
		t.Fail()
	}
}

func TestReadOpenSSHEd25519PrivateKeyEncrypted(t *testing.T) {
	keyFile, err := os.Open("../test/ssh-ed25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(privateKey[:]) != "604929f2b7340fbcf1504bcbb19362d3ac2f6b6970876a3d5a03526a7090f769" {
		t.Fail()
	}
}

func TestReadOpenSSHEd25519PublicKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssh-ed25519.pub")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(publicKey[:]) != "0fcfc907b2c7c236646ad01bbb5cffe7c7e0c54b69d41e8e71b213645760a83e" {
		t.Fail()
	}
}

func TestReadOpenSSLEd25519PrivateKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-ed25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(privateKey[:]) != "d0e6add79ffd6854ae7e007ce0979e51507d75b6b2fcac0f693595e318506b5d" {
		t.Fail()
	}
}

func TestReadOpenSSLEd25519PublicKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-ed25519.pub.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(publicKey[:]) != "fbf2f97a730336628b460c54991a9e8c3f9c293fba9a38404f6fb27d1054f327" {
		t.Fail()
	}
}

func TestReadOpenSSLX25519PrivateKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-x25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(privateKey[:]) != "602aa38d474f6c89a07840ddb5991d601eebada38062d3dc7e769b44546b4f41" {
		t.Fail()
	}
}

func TestReadOpenSSLX25519PublicKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-x25519.pub.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(publicKey[:]) != "e64dbe1ea253efce81b6e457881f90a03e2ee65b38a04776a75376955dfbce40" {
		t.Fail()
	}
}

func TestDerivePublicKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-x25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	publicKey := DerivePublicKey(privateKey)
	if hex.EncodeToString(publicKey[:]) != "e64dbe1ea253efce81b6e457881f90a03e2ee65b38a04776a75376955dfbce40" {
		t.Fail()
	}
}

func TestGenerateWriterSharedKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-ed25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/ssl-x25519.pub.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	sharedKey, err := GenerateWriterSharedKey(privateKey, publicKey)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString((*sharedKey)[:]) != "714a52792bf2118408c156da7d4f2973586ab923e6e263b6f7bec70c26eede97" {
		t.Fail()
	}
}

func TestGenerateReaderSharedKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-ed25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/ssl-x25519.pub.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	sharedKey, err := GenerateReaderSharedKey(privateKey, publicKey)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString((*sharedKey)[:]) != "e777a8500676b5999cdfbd5cd832abe2f31b2580d9d6ef359b03c808134b8a6f" {
		t.Fail()
	}
}
