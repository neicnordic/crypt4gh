package keys

import (
	"bytes"
	"encoding/hex"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

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

func TestGenerateKeyPair(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	derivedPublicKey := DerivePublicKey(privateKey)
	if !bytes.Equal(publicKey[:], derivedPublicKey[:]) {
		t.Fail()
	}
}

func TestReadKey(t *testing.T) {
	tests := []struct {
		name                   string
		readPrivateKeyFunction func(reader io.Reader, passPhrase []byte) (privateKey [chacha20poly1305.KeySize]byte, err error)
		readPublicKeyFunction  func(reader io.Reader) (publicKey [chacha20poly1305.KeySize]byte, err error)
		passPhrase             []byte
		hash                   string
	}{
		{
			name:                   "crypt4gh-x25519-enc.sec.pem",
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             []byte("password"),
			hash:                   "23917aa32d70294429f50899a0825c2ffdc07f98197dfc8195d6ea942a1914eb",
		},
		{
			name:                   "crypt4gh-x25519-enc.pub.pem",
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "cbaeec90614aa9837ed27fb53f4172c586bf9473d45a296837891daf1ec9dc10",
		},
		{
			name:                   "ssh-ed25519.sec.pem",
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             nil,
			hash:                   "384757a869e462b447543b33f251abc2b2d833da131c71fefe162c6f8c3e1640",
		},
		{
			name:                   "ssh-ed25519-enc.sec.pem",
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             []byte("123123"),
			hash:                   "604929f2b7340fbcf1504bcbb19362d3ac2f6b6970876a3d5a03526a7090f769",
		},
		{
			name:                   "ssh-ed25519.pub",
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "0fcfc907b2c7c236646ad01bbb5cffe7c7e0c54b69d41e8e71b213645760a83e",
		},
		{
			name:                   "ssl-ed25519.sec.pem",
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             nil,
			hash:                   "d0e6add79ffd6854ae7e007ce0979e51507d75b6b2fcac0f693595e318506b5d",
		},
		{
			name:                   "ssl-ed25519.pub.pem",
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "fbf2f97a730336628b460c54991a9e8c3f9c293fba9a38404f6fb27d1054f327",
		},
		{
			name:                   "ssl-x25519.sec.pem",
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             nil,
			hash:                   "602aa38d474f6c89a07840ddb5991d601eebada38062d3dc7e769b44546b4f41",
		},
		{
			name:                   "ssl-x25519.pub.pem",
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "e64dbe1ea253efce81b6e457881f90a03e2ee65b38a04776a75376955dfbce40",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyFile, err := os.Open("../test/" + test.name)
			if err != nil {
				t.Error(err)
			}
			var key [chacha20poly1305.KeySize]byte
			if test.readPrivateKeyFunction != nil {
				key, err = test.readPrivateKeyFunction(keyFile, test.passPhrase)
			} else {
				key, err = test.readPublicKeyFunction(keyFile)
			}
			if err != nil {
				t.Error(err)
			}
			if hex.EncodeToString(key[:]) != test.hash {
				t.Fail()
			}
		})
	}
}

func TestWriteOpenSSLX25519PrivateKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-x25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, nil)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteOpenSSLX25519PrivateKey(&buffer, privateKey)
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/ssl-x25519.sec.pem")
	if err != nil {
		t.Error(err)
	}
	keyFileBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyFileBytes, buffer.Bytes()) {
		t.Fail()
	}
}

func TestWriteOpenSSLX25519PublicKey(t *testing.T) {
	keyFile, err := os.Open("../test/ssl-x25519.pub.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteOpenSSLX25519PublicKey(&buffer, publicKey)
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/ssl-x25519.pub.pem")
	if err != nil {
		t.Error(err)
	}
	keyFileBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyFileBytes, buffer.Bytes()) {
		t.Fail()
	}
}

func TestWriteCrypt4GHX25519PrivateKey(t *testing.T) {
	keyFile, err := os.Open("../test/crypt4gh-x25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey, err := ReadPrivateKey(keyFile, []byte("password"))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteCrypt4GHX25519PrivateKey(&buffer, privateKey, []byte("password"))
	if err != nil {
		t.Error(err)
	}
	privateKeyReconstructed, err := ReadPrivateKey(&buffer, []byte("password"))
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(privateKeyReconstructed[:], privateKey[:]) {
		t.Fail()
	}
}

func TestWriteCrypt4GHX25519PublicKey(t *testing.T) {
	keyFile, err := os.Open("../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteCrypt4GHX25519PublicKey(&buffer, publicKey)
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		t.Error(err)
	}
	keyFileBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyFileBytes, buffer.Bytes()) {
		t.Fail()
	}
}

func TestGenerateSharedKey(t *testing.T) {
	tests := []struct {
		name           string
		privateKeyFile string
		publicKeyFile  string
		hash           string
	}{
		{
			name:           "Writer",
			privateKeyFile: "ssl-ed25519.sec.pem",
			publicKeyFile:  "ssl-x25519.pub.pem",
			hash:           "714a52792bf2118408c156da7d4f2973586ab923e6e263b6f7bec70c26eede97",
		},
		{
			name:           "Reader",
			privateKeyFile: "ssl-ed25519.sec.pem",
			publicKeyFile:  "ssl-x25519.pub.pem",
			hash:           "e777a8500676b5999cdfbd5cd832abe2f31b2580d9d6ef359b03c808134b8a6f",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyFile, err := os.Open("../test/" + test.privateKeyFile)
			if err != nil {
				t.Error(err)
			}
			privateKey, err := ReadPrivateKey(keyFile, nil)
			if err != nil {
				t.Error(err)
			}
			keyFile, err = os.Open("../test/" + test.publicKeyFile)
			if err != nil {
				t.Error(err)
			}
			publicKey, err := ReadPublicKey(keyFile)
			if err != nil {
				t.Error(err)
			}
			var sharedKey *[]byte
			if test.name == "Writer" {
				sharedKey, err = GenerateWriterSharedKey(privateKey, publicKey)
			} else {
				sharedKey, err = GenerateReaderSharedKey(privateKey, publicKey)
			}
			if err != nil {
				t.Error(err)
			}
			if hex.EncodeToString(*sharedKey) != test.hash {
				t.Fail()
			}
		})
	}
}
