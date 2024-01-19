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

func readerToReader(seekable bool, source io.Reader) io.Reader {
	if seekable {
		return source
	}
	return io.MultiReader(source)
}

func TestDecrypt(t *testing.T) {

	for _, seekable := range []bool{true, false} {

		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}

		inFile, err := os.Open("../test/sample.txt.enc")
		if err != nil {
			t.Error(err)
		}

		reader, err := NewCrypt4GHReader(readerToReader(seekable, inFile), readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}

		decBytes, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}

		refFile, err := os.Open("../test/sample.txt")
		if err != nil {
			t.Error(err)
		}
		refBytes, err := io.ReadAll(refFile)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(decBytes, refBytes) {
			t.Fail()
		}
	}
}

func TestReencryption(t *testing.T) {

	for _, seekable := range []bool{true, false} {

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

				readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
				if err != nil {
					t.Error(err)
				}

				reader, err := NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, nil)
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
}

func TestReencryptionWithDataEditListInCrypt4GHWriterNoDiscard(t *testing.T) {

	for _, seekable := range []bool{true, false} {

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
		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}

		reader, err := NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, nil)
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
}

func TestReencryptionWithDataEditListInCrypt4GHReaderNoDiscard(t *testing.T) {
	for _, seekable := range []bool{true, false} {

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

		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}
		dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
			PacketType:    headers.PacketType{PacketType: headers.DataEditList},
			NumberLengths: 4,
			Lengths:       []uint64{950, 837, 510, 847},
		}

		reader, err := NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, &dataEditListHeaderPacket)
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
}

func TestReencryptionWithDataEditListAndDiscard(t *testing.T) {
	for _, seekable := range []bool{true, false} {
		toDiscard := 100
		inFile, err := os.Open("../test/sample.txt")
		if err != nil {
			t.Error(err)
		}
		writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
		if err != nil {
			t.Errorf("Reading private key failed with %v", err)
		}
		readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
		if err != nil {
			t.Errorf("Reading public key failed with %v", err)
		}
		buffer := bytes.Buffer{}
		readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
		readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)
		writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKeyList, nil)
		if err != nil {
			t.Errorf("Creating writer failed with %v", err)
		}
		_, err = io.Copy(writer, inFile)
		if err != nil {
			t.Errorf("Copying infile to writer failed with %v", err)
		}
		err = inFile.Close()
		if err != nil {
			t.Errorf("Closing infile failed with %v", err)
		}
		err = writer.Close()
		if err != nil {
			t.Errorf("Closing writer failed with %v", err)
		}

		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Errorf("Reading private key failed with %v", err)
		}
		dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
			PacketType:    headers.PacketType{PacketType: headers.DataEditList},
			NumberLengths: 4,
			Lengths:       []uint64{950, 837, 510, 847},
		}

		reader, err := NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, &dataEditListHeaderPacket)
		if err != nil {
			t.Errorf("Creating reader failed with %v", err)
		}
		discarded, err := reader.Discard(toDiscard)
		if err != nil {
			t.Errorf("Discarding failed with %v", err)
		}
		if discarded != toDiscard {
			t.Errorf("Discarded return doesn't match was asked for %v != %v", discarded, toDiscard)
		}

		all, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("Reading all from reader failed with %v", err)
		}
		inFile, err = os.Open("../test/sample.txt")
		if err != nil {
			t.Errorf("Opening test sample failed with %v", err)
		}
		bufioReader := bufio.NewReader(inFile)
		_, err = bufioReader.Discard(950 + toDiscard)
		if err != nil {
			t.Errorf("Discarding failed with %v", err)
		}
		firstLine, _, err := bufioReader.ReadLine()
		if err != nil {
			t.Errorf("First Readline failed with %v", err)
		}
		_, _, err = bufioReader.ReadLine()
		if err != nil {
			t.Errorf("First Skipped Readline failed with %v", err)
		}
		_, _, err = bufioReader.ReadLine()
		if err != nil {
			t.Errorf("Second Skipped Readline failed with %v", err)
		}
		_, _, err = bufioReader.ReadLine()
		if err != nil {
			t.Errorf("Third Skipped Readline failed with %v", err)
		}
		secondLine, _, err := bufioReader.ReadLine()
		if err != nil {
			t.Errorf("Second used Readline failed with %v", err)
		}
		expectedText := strings.TrimSpace(string(firstLine) + "\n" + string(secondLine))
		actualText := strings.TrimSpace(string(all))

		if !strings.EqualFold(expectedText, actualText) {
			t.Errorf("Texts didn't match: %v, %v", expectedText, actualText)

		}
	}
}

func TestGetHeader(t *testing.T) {
	for _, seekable := range []bool{true, false} {

		inFile, err := os.Open("../test/sample.txt.enc")
		if err != nil {
			t.Error(err)
		}
		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}
		reader, err := NewCrypt4GHReader(readerToReader(seekable, inFile), readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}
		header := hex.EncodeToString(reader.GetHeader())
		if header != "637279707434676801000000010000006c00000000000000fcb2dcc7f1a915f30378b83de132bcaff3dba5ae68ac4c1b7fdaeb2c6ce9ca22aeb9f2121fce004f7d9069496804a55b9b376587000b921b33b18f8edad2db3b0c9f6bbd793be69592720710def70ca27451f4aa51d5ae7510c61f634a8d397f0de65630" {
			t.Error(header)
		}
		readByte, err := reader.ReadByte()
		if err != nil {
			t.Error(err)
		}
		if rune(readByte) != 'L' {
			t.Error()
		}
	}
}

func TestReencryptionWithDataEditListInCrypt4GHReaderDiscardStart(t *testing.T) {
	for _, seekable := range []bool{true, false} {
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

		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}
		dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
			PacketType:    headers.PacketType{PacketType: headers.DataEditList},
			NumberLengths: 3,
			Lengths:       []uint64{0, 100, 300},
		}
		reader, err := NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, &dataEditListHeaderPacket)
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
		if !bytes.Equal(all[:100], inBytes[:100]) {
			t.Errorf("Different data before discard: %v vs %v", all[:100], inBytes[:100])
		}
		if !bytes.Equal(all[100:], inBytes[400:]) {
			t.Errorf("Different data after discard: %v vs %v (truncated)", all[400:500], inBytes[100:200])
		}
	}
}

func TestNewCrypt4GHWriterWithoutPrivateKey(t *testing.T) {
	for _, seekable := range []bool{true, false} {

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

		reader, err := NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, nil)
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
}

// We encrypt a file with a recipient's public key and then we re-encrypt it with another
// new public key and we try to decrypt it with that
func TestFileReEncryption(t *testing.T) {
	for _, seekable := range []bool{true, false} {
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

		reader, err := NewCrypt4GHReader(readerToReader(seekable, reencryptedFile), newReaderSecretKey, nil)
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
}

// TestConsumerToUnderlying verifies functionality of
// consumerOffsetToEncryptedStreamOffset.
func TestConsumerToUnderlying(t *testing.T) {

	del := &headers.DataEditListHeaderPacket{NumberLengths: 0}
	c := crypt4GHInternalReader{}

	r, err := c.consumerOffsetToEncryptedStreamOffset(10)
	if r != 10 || err != nil {
		t.Errorf("Conversion of consumer to underlying offset without DEL failed")
	}

	c.dataEditList = del
	r, err = c.consumerOffsetToEncryptedStreamOffset(10)
	if r != 10 || err != nil {
		t.Errorf("Conversion of consumer to underlying offset with 0-DEL failed")
	}

	del.NumberLengths = 4
	del.Lengths = []uint64{10, 20, 30, 40}

	r, err = c.consumerOffsetToEncryptedStreamOffset(10)
	if r != 20 || err != nil {
		t.Errorf("Conversion of consumer to underlying failed, first hole")
	}

	r, err = c.consumerOffsetToEncryptedStreamOffset(20)
	if r != 60 || err != nil {
		t.Errorf("Conversion of consumer to underlying failed, two holes")
	}

	r, err = c.consumerOffsetToEncryptedStreamOffset(200)
	if r != 100 || err == nil {
		t.Errorf("Conversion of consumer to underlying EOF failed, got %d, %v", r, err)
	}

	del.NumberLengths = 3
	r, err = c.consumerOffsetToEncryptedStreamOffset(200)
	if r != 240 || err != nil {
		t.Errorf("Conversion of consumer to underlying last infinite failed")
	}

}

// TestBrokenFileRead verifies proper errors on reading broken files
func TestBrokenFileRead(t *testing.T) {
	for _, seekable := range []bool{true, false} {
		_, err := NewCrypt4GHReader(readerToReader(seekable, bytes.NewBuffer([]byte{})), [32]byte{}, nil)
		if err == nil {
			t.Errorf("Didn't get error for a reader for an empty file")
		}

		_, err = NewCrypt4GHReader(readerToReader(seekable, bytes.NewBuffer([]byte{'c', 'r'})), [32]byte{}, nil)
		if err == nil {
			t.Errorf("Didn't get error for a reader for an empty file")
		}
	}
}

// TestFillBuffer verifies fillBuffer functionality
func TestFillBuffer(t *testing.T) {
	for _, seekable := range []bool{true, false} {

		c := crypt4GHInternalReader{encryptedSegmentSize: 1024}
		c.reader = bytes.NewBuffer([]byte{})

		err := c.fillBuffer()
		if err == nil {
			t.Errorf("Didn't get error for a reader for an empty file")
		}

		_, err = NewCrypt4GHReader(readerToReader(seekable, bytes.NewBuffer([]byte{'c', 'r'})), [32]byte{}, nil)
		if err == nil {
			t.Errorf("Didn't get error for a reader for an empty file")
		}

		del := &headers.DataEditListHeaderPacket{}
		del.NumberLengths = 4
		del.Lengths = []uint64{10, 20, 30, 40}
		c.dataEditList = del

		c.streamPos = 4000
		err = c.fillBuffer()
		if err == nil {
			t.Errorf("Didn't get error for beyond file according to skiplist")
		}

	}
}

func TestClose(t *testing.T) {
	for _, seekable := range []bool{true, false} {
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

		buf1 := buffer.Bytes()
		buf2 := bytes.Clone(buf1)
		bufferReader := bytes.NewReader(buf1)

		reader, err := NewCrypt4GHReader(readerToReader(seekable, bufferReader), readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}

		err = reader.Close()
		if err != nil {
			t.Error("Closing bytes.Reader failed")
		}
		closerReader := readerToReader(seekable, io.NopCloser(bytes.NewReader(buf2)))

		reader, err = NewCrypt4GHReader(closerReader, readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}

		err = reader.Close()
		if err != nil {
			t.Error("Closing NopCloser failed")
		}
	}
}

func TestLargeSeek(t *testing.T) {
	for _, seekable := range []bool{true, false} {
		inFile, err := os.Open("../test/sample.txt")
		if err != nil {
			t.Error(err)
		}

		inBytes, err := io.ReadAll(inFile)
		if err != nil {
			t.Error(err)
		}

		if err = inFile.Close(); err != nil {
			t.Error(err)
		}

		readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
		if err != nil {
			t.Error(err)
		}
		buffer := bytes.Buffer{}

		readerPublicKeyList := [][chacha20poly1305.KeySize]byte{}
		readerPublicKeyList = append(readerPublicKeyList, readerPublicKey)

		writer, err := NewCrypt4GHWriterWithoutPrivateKey(&buffer, readerPublicKeyList, nil)
		if err != nil {
			t.Error(err)
		}

		for i := 0; i < 32; i++ {
			if r, err := writer.Write(inBytes[:20000]); err != nil || r != 20000 {
				t.Errorf("Problem when writing to cryptgh writer, r=%d, err=%v", r, err)
			}
		}

		err = writer.Close()
		if err != nil {
			t.Error(err)
		}
		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}

		bufferReader := bytes.NewReader(buffer.Bytes())

		reader, err := NewCrypt4GHReader(readerToReader(seekable, bufferReader), readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}

		offset, err := reader.Seek(130000, 0)
		if err != nil {
			t.Errorf("Seeking failed, returned offset=%v, err=%v", offset, err)
		}

		buf := make([]byte, 4096)
		r, err := reader.Read(buf)
		if err != nil || r != len(buf) {
			t.Errorf("Read returned unexpected r=%v, err=%v", r, err)
		}

		if !bytes.Equal(buf, inBytes[10000:14096]) {
			t.Errorf("Content mismatch when passing segment boundary")
		}
	}
}

func TestSeek(t *testing.T) {
	for _, seekable := range []bool{true, false} {

		inFile, err := os.Open("../test/sample.txt")
		if err != nil {
			t.Error(err)
		}

		inBytes, err := io.ReadAll(inFile)
		if err != nil {
			t.Error(err)
		}

		if err = inFile.Close(); err != nil {
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

		if r, err := writer.Write(inBytes); err != nil || r != len(inBytes) {
			t.Errorf("Problem when writing to cryptgh writer, r=%d, err=%v", r, err)
		}

		err = writer.Close()
		if err != nil {
			t.Error(err)
		}
		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}

		bufferReader := bytes.NewReader(buffer.Bytes())

		reader, err := NewCrypt4GHReader(readerToReader(seekable, bufferReader), readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}

		_, err = reader.Seek(0, 2)
		if err == nil {
			t.Error("Seeking from end should not be allowed")
		}

		_, err = reader.Seek(100, 10)
		if err == nil {
			t.Error("Bad whence should not be allowed")
		}

		r, err := reader.Seek(60, 0)
		if err != nil || r != 60 {
			t.Error("Seeking from start failed")
		}

		r, err = reader.Seek(50, 1)
		if err != nil || r != 110 {
			t.Error("Seeking forward failed")
		}

		all, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(all[:727], inBytes[1060:1060+727]) {
			t.Error("Mismatch after seek")
		}

		r, err = reader.Seek(10, 0)
		if !seekable {
			// Not going backwards is fine when not seekable, check for error

			if err == nil {
				t.Error("Seeking backward didn't error when it should")
			}
		} else {
			// If seekable, we can go backwards, check things
			if err != nil || r != 10 {
				t.Error("Seeking backward failed")
			}

			all, err = io.ReadAll(reader)

			if err != nil {
				t.Errorf("Failed when reading after seek %v", err)
			}

			if !bytes.Equal(all[:827], inBytes[960:960+827]) || !bytes.Equal(all[827:827+847], inBytes[950+837+510:950+837+510+847]) {
				t.Error("Mismatch after seek backwards")
			}
		}

		// Refill buffer
		buffer.Reset()
		writer, err = NewCrypt4GHWriterWithoutPrivateKey(&buffer, readerPublicKeyList, &dataEditListHeaderPacket)
		if err != nil {
			t.Error(err)
		}

		if r, err := writer.Write(inBytes); err != nil || r != len(inBytes) {
			t.Errorf("Problem when writing to cryptgh writer, r=%d, err=%v", r, err)
		}

		err = writer.Close()
		if err != nil {
			t.Error(err)
		}

		dataEditListHeaderPacket.NumberLengths = 0
		reader, err = NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, &dataEditListHeaderPacket)
		if err != nil {
			t.Errorf("Error while making reader from buffer %v", err)
		}

		if r, err = reader.Seek(70000, 0); err != nil || r != 70000 {
			t.Error("Seeking forward failed")
		}

		if r, err = reader.Seek(10, 0); err == nil || r == 10 {
			t.Error("Seeking back worked when it wasn't expected")
		}

		buf := make([]byte, 10)
		if s, err := reader.Read(buf); err != nil || s != 10 {
			t.Error("Read after seek failed")
		}

		if !bytes.Equal(buf, inBytes[70000:70010]) {
			t.Error("Mismatch after seek")
		}

		// Refill buffer
		buffer.Reset()
		writer, err = NewCrypt4GHWriterWithoutPrivateKey(&buffer, readerPublicKeyList, &dataEditListHeaderPacket)
		if err != nil {
			t.Error(err)
		}

		if r, err := writer.Write(inBytes[:70225]); err != nil || r != 70225 {
			t.Errorf("Problem when writing to cryptgh writer, r=%d, err=%v", r, err)
		}

		err = writer.Close()
		if err != nil {
			t.Error(err)
		}

		reader, err = NewCrypt4GHReader(readerToReader(seekable, &buffer), readerSecretKey, &dataEditListHeaderPacket)
		if err != nil {
			t.Errorf("Error while making reader from buffer again %v", err)
		}

		if r, err = reader.Seek(70000, 0); err != nil || r != 70000 {
			t.Errorf("Seeking a long bit failed (r=%d, err=%v)", r, err)
		}

		buf = make([]byte, 50000)
		buf[225] = 42
		buf[226] = 137

		if s, err := reader.Read(buf); err != io.EOF || s != 225 {
			t.Errorf("Read after seek failed (got s=%d, err=%v)", s, err)
		}

		if !bytes.Equal(buf[:225], inBytes[70000:70000+225]) {
			t.Error("Read didn't return the expected data")
		}

		if buf[225] != 42 || buf[226] != 137 {
			t.Error("Read touched data unexpectedly")
		}
	}
}

func TestSmallBuffer(t *testing.T) {
	for _, seekable := range []bool{true, false} {

		inFile, err := os.Open("../test/sample.txt")
		if err != nil {
			t.Error(err)
		}
		inBytes, err := io.ReadAll(inFile)
		if err != nil {
			t.Error(err)
		}

		if err = inFile.Close(); err != nil {
			t.Error(err)
		}

		inFile, err = os.Open("../test/sample.txt")
		if err != nil {
			t.Error(err)
		}
		readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
		if err != nil {
			t.Error(err)
		}
		dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
			PacketType:    headers.PacketType{PacketType: headers.DataEditList},
			NumberLengths: 8,
			Lengths:       []uint64{10, 20, 30, 40, 950, 837, 510, 847},
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

		if _, err = io.Copy(writer, inFile); err != nil {
			t.Error(err)
		}

		if err = inFile.Close(); err != nil {
			t.Error(err)
		}

		if err = writer.Close(); err != nil {
			t.Error(err)
		}

		readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
		if err != nil {
			t.Error(err)
		}

		bufferReader := bytes.NewReader(buffer.Bytes())

		reader, err := NewCrypt4GHReader(readerToReader(seekable, bufferReader), readerSecretKey, nil)
		if err != nil {
			t.Error(err)
		}

		buf := make([]byte, 5)

		r, err := reader.Read(buf)
		if err != nil || r != 5 {
			t.Error("Seeking from end should not be allowed")
		}

		if !bytes.Equal(buf, inBytes[10:15]) {
			t.Error("Mismatch after first read")
		}

		s, err := reader.Seek(18, 0)
		if err != nil || s != 18 {
			t.Error("Seeking failed")
		}

		r, err = reader.Read(buf)
		if err != nil || r != 5 {
			t.Errorf("Reading failed r=%d err=%v", r, err)
		}

		if !bytes.Equal(buf[:2], inBytes[28:30]) && !bytes.Equal(buf[2:], inBytes[60:63]) {
			t.Error("Mismatch after second read")
		}
	}
}
