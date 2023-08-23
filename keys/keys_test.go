package keys

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

const crypt4ghX25519Sec = `-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----
YzRnaC12MQAGc2NyeXB0ABQAAAAAbY7POWSS/pYIR8zrPQZJ+QARY2hhY2hhMjBfcG9seTEzMDUAPKc4jWLf1h2T5FsPhNUYMMZ8y36ESATXOuloI0uxKxov3OZ/EbW0Rj6XY0pd7gcBLQDFwakYB7KMgKjiCAAA
-----END CRYPT4GH ENCRYPTED PRIVATE KEY-----
`
const crypt4ghX25519Pub = `-----BEGIN CRYPT4GH PUBLIC KEY-----
y67skGFKqYN+0n+1P0FyxYa/lHPUWiloN4kdrx7J3BA=
-----END CRYPT4GH PUBLIC KEY-----
`
const badPEM = `-----BEGIN SOMETHING-----
y67s
-----END SOMETHING-----
`
const sshEd25519SecEnc = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCKYb3joJ
xaRg4JDkveDbaTAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIA65hmgJeJakva2c
tMpwAqifM/904s6O1zkwLeS5WiDDAAAAoLwLn+qb6fvbYvPn5VuK2IY94BGFlxPdsJElH0
qLE4/hhZiDTXKv7sxup9ZXeJ5ZS5pvFRFPqODCBG87JlbpNBra5pbywpyco89Gr+B0PHff
PR84IfM7rbdETegmHhq6rX9HGSWhA2Hqa3ntZ2dDD+HUtzdGi3zRPAFLCF0uy3laaiBItC
VgFxmKhQ85221EUcMSEk6ophcCe8thlrtxjZk=
-----END OPENSSH PRIVATE KEY-----
`

// not used but kept for backwards compatibility
// const sshEd25519PubEnc = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA65hmgJeJakva2ctMpwAqifM/904s6O1zkwLeS5WiDD dmytrot@Dmytros-MBP.Dlink
// `

const sshEd25519Sec = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBkoVLW4MQ+9Bo/mpcLqYzx6U3iB3/7O6VjX8ddFb2B1QAAAKjEv9haxL/Y
WgAAAAtzc2gtZWQyNTUxOQAAACBkoVLW4MQ+9Bo/mpcLqYzx6U3iB3/7O6VjX8ddFb2B1Q
AAAEBXSyEXVFeTcD4UmmMqpEV79uYeE12FR1clB0AyWQC2zmShUtbgxD70Gj+alwupjPHp
TeIHf/s7pWNfx10VvYHVAAAAIWRteXRyb3RARG15dHJvcy1NYWNCb29rLVByby5sb2NhbA
ECAwQ=
-----END OPENSSH PRIVATE KEY-----
`

const sshEd25519Pub = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGShUtbgxD70Gj+alwupjPHpTeIHf/s7pWNfx10VvYHV dmytrot@Dmytros-MacBook-Pro.local
`

const sslEd25519Sec = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID7AAAQNzabPfcuNdPO7o3nFvxMQnBwrKA3h9L337Fjv
-----END PRIVATE KEY-----
`

const sslEd25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApkjFepMCo7sEUGpN44Ao1cVi+S+LZSSG4uei6Ri+DW4=
-----END PUBLIC KEY-----
`

const sslX25519Sec = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIGAqo41HT2yJoHhA3bWZHWAe662jgGLT3H52m0RUa09B
-----END PRIVATE KEY-----
`

const sslX25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEA5k2+HqJT786BtuRXiB+QoD4u5ls4oEd2p1N2lV37zkA=
-----END PUBLIC KEY-----
`

func TestDerivePublicKey(t *testing.T) {
	privateKey, err := ReadPrivateKey(strings.NewReader(sslX25519Sec), nil)
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
		content                string
		readPrivateKeyFunction func(reader io.Reader, passPhrase []byte) (privateKey [chacha20poly1305.KeySize]byte, err error)
		readPublicKeyFunction  func(reader io.Reader) (publicKey [chacha20poly1305.KeySize]byte, err error)
		passPhrase             []byte
		hash                   string
	}{
		{
			name:                   "crypt4gh-x25519-enc.sec.pem",
			content:                crypt4ghX25519Sec,
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             []byte("password"),
			hash:                   "23917aa32d70294429f50899a0825c2ffdc07f98197dfc8195d6ea942a1914eb",
		},
		{
			name:                   "crypt4gh-x25519-enc.pub.pem",
			content:                crypt4ghX25519Pub,
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "cbaeec90614aa9837ed27fb53f4172c586bf9473d45a296837891daf1ec9dc10",
		},
		{
			name:                   "ssh-ed25519.sec.pem",
			content:                sshEd25519Sec,
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             nil,
			hash:                   "384757a869e462b447543b33f251abc2b2d833da131c71fefe162c6f8c3e1640",
		},
		{
			name:                   "ssh-ed25519-enc.sec.pem",
			content:                sshEd25519SecEnc,
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             []byte("123123"),
			hash:                   "604929f2b7340fbcf1504bcbb19362d3ac2f6b6970876a3d5a03526a7090f769",
		},
		{
			name:                   "ssh-ed25519.pub",
			content:                sshEd25519Pub,
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "0fcfc907b2c7c236646ad01bbb5cffe7c7e0c54b69d41e8e71b213645760a83e",
		},
		{
			name:                   "ssl-ed25519.sec.pem",
			content:                sslEd25519Sec,
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             nil,
			hash:                   "d0e6add79ffd6854ae7e007ce0979e51507d75b6b2fcac0f693595e318506b5d",
		},
		{
			name:                   "ssl-ed25519.pub.pem",
			content:                sslEd25519Pub,
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "fbf2f97a730336628b460c54991a9e8c3f9c293fba9a38404f6fb27d1054f327",
		},
		{
			name:                   "ssl-x25519.sec.pem",
			content:                sslX25519Sec,
			readPrivateKeyFunction: ReadPrivateKey,
			readPublicKeyFunction:  nil,
			passPhrase:             nil,
			hash:                   "602aa38d474f6c89a07840ddb5991d601eebada38062d3dc7e769b44546b4f41",
		},
		{
			name:                   "ssl-x25519.pub.pem",
			content:                sslX25519Pub,
			readPrivateKeyFunction: nil,
			readPublicKeyFunction:  ReadPublicKey,
			passPhrase:             nil,
			hash:                   "e64dbe1ea253efce81b6e457881f90a03e2ee65b38a04776a75376955dfbce40",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var err error
			var key [chacha20poly1305.KeySize]byte
			if test.readPrivateKeyFunction != nil {
				key, err = test.readPrivateKeyFunction(strings.NewReader(test.content), test.passPhrase)
			} else {
				key, err = test.readPublicKeyFunction(strings.NewReader(test.content))
			}

			if err != nil {
				t.Errorf("Unexpected error: %v for test %s", err, test.name)
			}
			if hex.EncodeToString(key[:]) != test.hash {
				t.Fail()
			}
		})
	}
}

func TestWriteOpenSSLX25519PrivateKey(t *testing.T) {
	privateKey, err := ReadPrivateKey(strings.NewReader(sslX25519Sec), nil)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteOpenSSLX25519PrivateKey(&buffer, privateKey)
	if err != nil {
		t.Error(err)
	}
	keyFile := strings.NewReader(sslX25519Sec)

	keyFileBytes, err := io.ReadAll(keyFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyFileBytes, buffer.Bytes()) {
		t.Fail()
	}
}

func TestWriteOpenSSLX25519PublicKey(t *testing.T) {
	publicKey, err := ReadPublicKey(strings.NewReader(sslX25519Pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteOpenSSLX25519PublicKey(&buffer, publicKey)
	if err != nil {
		t.Error(err)
	}
	keyFile := strings.NewReader(sslX25519Pub)

	keyFileBytes, err := io.ReadAll(keyFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyFileBytes, buffer.Bytes()) {
		t.Fail()
	}
}

func TestWriteCrypt4GHX25519PrivateKey(t *testing.T) {

	privateKey, err := ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
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

	publicKey, err := ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	err = WriteCrypt4GHX25519PublicKey(&buffer, publicKey)
	if err != nil {
		t.Error(err)
	}
	keyFile := strings.NewReader(crypt4ghX25519Pub)
	keyFileBytes, err := io.ReadAll(keyFile)
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
			privateKeyFile: sslEd25519Sec,
			publicKeyFile:  sslX25519Pub,
			hash:           "714a52792bf2118408c156da7d4f2973586ab923e6e263b6f7bec70c26eede97",
		},
		{
			name:           "Reader",
			privateKeyFile: sslEd25519Sec,
			publicKeyFile:  sslX25519Pub,
			hash:           "e777a8500676b5999cdfbd5cd832abe2f31b2580d9d6ef359b03c808134b8a6f",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyFile := strings.NewReader(test.privateKeyFile)

			privateKey, err := ReadPrivateKey(keyFile, nil)
			if err != nil {
				t.Error(err)
			}
			keyFile = strings.NewReader(test.publicKeyFile)
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

func TestReadBrokenKey(t *testing.T) {

	if _, err := ReadPrivateKey(strings.NewReader("error"), nil); err == nil {
		t.Errorf("Didn't get an error on a faulty private key")
	}

	if _, err := ReadPublicKey(strings.NewReader("error")); err == nil {
		t.Errorf("Didn't get an error on a faulty public key")
	}

	if _, err := ReadPrivateKey(strings.NewReader(badPEM), nil); err == nil {
		t.Errorf("Didn't get an error on a faulty private key")
	}

	if _, err := ReadPublicKey(strings.NewReader(badPEM)); err == nil {
		t.Errorf("Didn't get an error on a faulty public key")
	}

	if _, err := ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), nil); err == nil {
		t.Errorf("Didn't get an error on an encrypted private key without password")
	}

}
