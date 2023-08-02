package streaming

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
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

const sshEd25519SecEnc = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCKYb3joJ
xaRg4JDkveDbaTAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIA65hmgJeJakva2c
tMpwAqifM/904s6O1zkwLeS5WiDDAAAAoLwLn+qb6fvbYvPn5VuK2IY94BGFlxPdsJElH0
qLE4/hhZiDTXKv7sxup9ZXeJ5ZS5pvFRFPqODCBG87JlbpNBra5pbywpyco89Gr+B0PHff
PR84IfM7rbdETegmHhq6rX9HGSWhA2Hqa3ntZ2dDD+HUtzdGi3zRPAFLCF0uy3laaiBItC
VgFxmKhQ85221EUcMSEk6ophcCe8thlrtxjZk=
-----END OPENSSH PRIVATE KEY-----
`

const newRecipientPub = `-----BEGIN CRYPT4GH PUBLIC KEY-----
NZfoJzFcOli3UWi/7U624h6fv2PufL1i2QPK8JkpmFg=
-----END CRYPT4GH PUBLIC KEY-----
`

const newRecipientSec = `-----BEGIN CRYPT4GH PRIVATE KEY-----
YzRnaC12MQAGc2NyeXB0ABQAAAAA2l23+H3w2F3/Zylx5Gs2CwARY2hhY2hhMjBfcG9seTEzMDUAPOdxRff6MecEU3E3IMN/xfIwpMQNhpGVM2E+qExbEnZkoYx8sOuhWi8ASYmhFgxcrLj7Q9nOGQpXfukgpg==
-----END CRYPT4GH PRIVATE KEY-----
`

func TestReencryption(t *testing.T) {
	tests := []struct {
		name    string
		discard int
	}{
		{
			name:    "no discard",
			discard: 0,
		},
		{
			name:    "within the first segment",
			discard: 100,
		},
		{
			name:    "on the edge",
			discard: headers.UnencryptedDataSegmentSize,
		},
		{
			name:    "within the second segment",
			discard: headers.UnencryptedDataSegmentSize + 100,
		},
		{
			name:    "out of range",
			discard: headers.UnencryptedDataSegmentSize * 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inFile, err := os.Open("../test/sample.txt")
			if err != nil {
				t.Error(err)
			}
			writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
			if err != nil {
				t.Error(err)
			}
			readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
			if err != nil {
				t.Error(err)
			}
			readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
			readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
			buffer := bytes.Buffer{}
			writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil, nil)
			if err != nil {
				t.Error(err)
			}
			_, err = io.Copy(writer, inFile)
			if err != nil {
				t.Error(err)
			}
			err = inFile.Close()
			if err != nil {
				t.Error(err)
			}
			err = writer.Close()
			if err != nil {
				t.Error(err)
			}

			readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
			if err != nil {
				t.Error(err)
			}
			reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, nil)
			if err != nil {
				t.Error(err)
			}
			discarded, err := reader.Discard(test.discard)
			if err != nil {
				if test.discard != headers.UnencryptedDataSegmentSize*2 {
					t.Error(err)
				}
			}
			if discarded != test.discard {
				if test.discard != headers.UnencryptedDataSegmentSize*2 {
					t.Fail()
				}
			}
			all, err := io.ReadAll(reader)
			if err != nil {
				t.Error(err)
			}
			inFile, err = os.Open("../test/sample.txt")
			if err != nil {
				t.Error(err)
			}
			inBytes, err := io.ReadAll(inFile)
			if err != nil {
				t.Error(err)
			}
			toDiscard := test.discard
			if test.discard > len(inBytes) {
				toDiscard = len(inBytes)
			}
			if !bytes.Equal(all, inBytes[toDiscard:]) {
				t.Fail()
			}
		})
	}
}

func TestReencryptionWithDataEditListInCrypt4GHWriterNoDiscard(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, &dataEditListHeaderPacket, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, nil)
	if err != nil {
		t.Error(err)
	}
	all, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	inBytes, err := io.ReadAll(inFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(all[:837], inBytes[950:950+837]) {
		t.Fail()
	}
}

func TestReencryptionWithDataEditListInCrypt4GHReaderNoDiscard(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, &dataEditListHeaderPacket)
	if err != nil {
		t.Error(err)
	}
	all, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	inBytes, err := io.ReadAll(inFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(all[:837], inBytes[950:950+837]) {
		t.Fail()
	}
}

func TestReencryptionWithDataEditListAndDiscard(t *testing.T) {
	toDiscard := 100
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, &dataEditListHeaderPacket)
	if err != nil {
		t.Error(err)
	}
	discarded, err := reader.Discard(toDiscard)
	if err != nil {
		t.Error(err)
	}
	if discarded != toDiscard {
		t.Fail()
	}
	all, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	bufioReader := bufio.NewReader(inFile)
	_, err = bufioReader.Discard(950 + toDiscard)
	if err != nil {
		t.Error(err)
	}
	firstLine, _, err := bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	_, _, err = bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	_, _, err = bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	_, _, err = bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	secondLine, _, err := bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	expectedText := strings.TrimSpace(string(firstLine) + "\n" + string(secondLine))
	actualText := strings.TrimSpace(string(all))
	if !strings.EqualFold(expectedText, actualText) {
		t.Fail()
	}
}

func TestGetHeader(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt.enc")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	reader, err := NewCrypt4GHReader(inFile, readerSecretKey, nil)
	if err != nil {
		t.Error(err)
	}
	header := hex.EncodeToString(reader.GetHeader())
	if header != "637279707434676801000000010000006c000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b9ed06c98c3183938aec96dd7b39258b80c4291ef23d4f16a4a35f52f95a25d7b6121d9646c94994c7cacfe3c98d4cb8122213b2475909fdc1e16f322e57095129cd87a6a" {
		t.Error()
	}
	readByte, err := reader.ReadByte()
	if err != nil {
		t.Error(err)
	}
	if rune(readByte) != 'L' {
		t.Error()
	}
}

func TestNewCrypt4GHWriterWithoutPrivateKey(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	if len(readerPublicKeyList) != 3 {
		t.Errorf("expected %d public keys in list but got %d", 3, len(readerPublicKeyList))
	}
	writer, err := NewCrypt4GHWriterWithoutPrivateKey(&buffer, readerPublicKeyList, &dataEditListHeaderPacket)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, nil)
	if err != nil {
		t.Error(err)
	}
	all, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	inBytes, err := io.ReadAll(inFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(all[:837], inBytes[950:950+837]) {
		t.Fail()
	}
}

// We encrypt a file with a recipient's public key and then we re-encrypt it with another
// new public key and we try to decrypt it with that
func TestFileReEncryption(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	newReaderPublicKey, err := keys.ReadPublicKey(strings.NewReader(newRecipientPub))
	if err != nil {
		t.Error(err)
	}
	newReaderPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	newReaderPublicKeyList = append(newReaderPublicKeyList, newReaderPublicKey)

	reencryptedFile, err := ReCrypt4GHWriter(&buffer, readerSecretKey, newReaderPublicKeyList)
	if err != nil {
		t.Error(err)
	}

	newReaderSecretKey, err := keys.ReadPrivateKey(strings.NewReader(newRecipientSec), []byte("password"))
	if err != nil {
		t.Error(err)
	}

	reader, err := NewCrypt4GHReader(reencryptedFile, newReaderSecretKey, nil)
	if err != nil {
		t.Error(err)
	}
	discarded, err := reader.Discard(0)
	if err != nil {
		if 0 != headers.UnencryptedDataSegmentSize*2 {
			t.Error(err)
		}
	}
	if discarded != 0 {
		if 0 != headers.UnencryptedDataSegmentSize*2 {
			t.Fail()
		}
	}
	all, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	inBytes, err := io.ReadAll(inFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(all, inBytes[0:]) {
		t.Fail()
	}
}

func TestNewCrypt4GHWriterWithNonces(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	if len(readerPublicKeyList) != 3 {
		t.Errorf("expected %d public keys in list but got %d", 3, len(readerPublicKeyList))
	}
	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return
	}
	writer, err := NewCrypt4GHWriter(&buffer, privateKey, readerPublicKeyList, nil, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	_, err = inFile.Seek(0, io.SeekStart)
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	buffer2 := bytes.Buffer{}
	writer2, err := NewCrypt4GHWriter(&buffer2, privateKey, readerPublicKeyList, nil, writer.Rands)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer2, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer2.Close()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(buffer.Bytes(), buffer2.Bytes()) {
		t.Fail()
	}
}
