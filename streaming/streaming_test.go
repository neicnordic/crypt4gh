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

const crypt4gh_x25519_sec = `-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----
YzRnaC12MQAGc2NyeXB0ABQAAAAAbY7POWSS/pYIR8zrPQZJ+QARY2hhY2hhMjBfcG9seTEzMDUAPKc4jWLf1h2T5FsPhNUYMMZ8y36ESATXOuloI0uxKxov3OZ/EbW0Rj6XY0pd7gcBLQDFwakYB7KMgKjiCAAA
-----END CRYPT4GH ENCRYPTED PRIVATE KEY-----
`
const crypt4gh_x25519_pub = `-----BEGIN CRYPT4GH PUBLIC KEY-----
y67skGFKqYN+0n+1P0FyxYa/lHPUWiloN4kdrx7J3BA=
-----END CRYPT4GH PUBLIC KEY-----
`

const ssh_ed25519_sec_enc = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCKYb3joJ
xaRg4JDkveDbaTAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIA65hmgJeJakva2c
tMpwAqifM/904s6O1zkwLeS5WiDDAAAAoLwLn+qb6fvbYvPn5VuK2IY94BGFlxPdsJElH0
qLE4/hhZiDTXKv7sxup9ZXeJ5ZS5pvFRFPqODCBG87JlbpNBra5pbywpyco89Gr+B0PHff
PR84IfM7rbdETegmHhq6rX9HGSWhA2Hqa3ntZ2dDD+HUtzdGi3zRPAFLCF0uy3laaiBItC
VgFxmKhQ85221EUcMSEk6ophcCe8thlrtxjZk=
-----END OPENSSH PRIVATE KEY-----
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
			writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(ssh_ed25519_sec_enc), []byte("123123"))
			if err != nil {
				t.Error(err)
			}
			readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4gh_x25519_pub))
			if err != nil {
				t.Error(err)
			}
			readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
			readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
			buffer := bytes.Buffer{}
			writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil)
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

			readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4gh_x25519_sec), []byte("password"))
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
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(ssh_ed25519_sec_enc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4gh_x25519_pub))
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
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, &dataEditListHeaderPacket)
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
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4gh_x25519_sec), []byte("password"))
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
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(ssh_ed25519_sec_enc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4gh_x25519_pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil)
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

	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4gh_x25519_sec), []byte("password"))
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
	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(ssh_ed25519_sec_enc), []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4gh_x25519_pub))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil)
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

	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4gh_x25519_sec), []byte("password"))
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
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4gh_x25519_sec), []byte("password"))
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
