package headers

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/neicnordic/crypt4gh/keys"
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

func TestHeaderMarshallingWithNonce(t *testing.T) {

	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
	if err != nil {
		t.Errorf("Reading private key from string failed: %v", err)
	}

	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Errorf("Reading public key from string failed: %v", err)
	}
	var nonce = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	magic := [8]byte{}
	copy(magic[:], MagicNumber)
	header := Header{
		MagicNumber:       magic,
		Version:           1,
		HeaderPacketCount: 2,
		HeaderPackets: []HeaderPacket{{
			WriterPrivateKey:       writerPrivateKey,
			ReaderPublicKey:        readerPublicKey,
			PacketLength:           10,
			HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
			Nonce:                  &nonce,
			EncryptedHeaderPacket: DataEncryptionParametersHeaderPacket{
				EncryptedSegmentSize: 10,
				PacketType:           PacketType{DataEncryptionParameters},
				DataEncryptionMethod: ChaCha20IETFPoly1305,
				DataKey:              [32]byte{},
			},
		},
			{
				WriterPrivateKey:       writerPrivateKey,
				ReaderPublicKey:        readerPublicKey,
				PacketLength:           10,
				HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
				Nonce:                  &nonce,
				EncryptedHeaderPacket: DataEditListHeaderPacket{
					PacketType:    PacketType{DataEditList},
					NumberLengths: 3,
					Lengths:       []uint64{1, 2, 3},
				},
			},
		},
	}
	marshalledHeader, err := header.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(marshalledHeader) != "637279707434676801000000020000006c000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b0102030405060708090a0b0c8f5854ea6eceff229d474a1f35af0c7b9813ccc1ff370a56a630018203f102d99e83bd6e6cad47cc6d8185d1fa9ea800aedad79f47042ca364000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b0102030405060708090a0b0c8e5854ea6dceff229c474a1f35af0c7b9a13ccc1ff370a56a530018203f102d9bb97386e42d0695f862312bd04206bb6" {
		t.Fail()
	}
}

func TestNewHeader(t *testing.T) {
	decodedHeader, err := hex.DecodeString("637279707434676801000000020000006c000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b0102030405060708090a0b0c8f5854ea6eceff229d474a1f35af0c7b9813ccc1ff370a56a630018203f102d99e83bd6e6cad47cc6d8185d1fa9ea800aedad79f47042ca364000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b0102030405060708090a0b0c8e5854ea6dceff229c474a1f35af0c7b9a13ccc1ff370a56a530018203f102d9bb97386e42d0695f862312bd04206bb6")
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.NewBuffer(decodedHeader)
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Errorf("Reading private key from string failed: %v", err)
	}
	header, err := NewHeader(buffer, readerSecretKey)
	if err != nil {
		t.Errorf("NewHeader failed unexpectedly: %v", err)
	}
	if fmt.Sprintf("%v", header) != "&{[99 114 121 112 116 52 103 104] 1 2 [{[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] 108 0 <nil> {65564 {0} 0 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}} {[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] 100 0 <nil> {{1} 3 [1 2 3]}}]}" {
		t.Fail()
	}
}

func TestReadHeader(t *testing.T) {
	inFile, err := os.Open("../../test/sample.txt.enc")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	header, err := ReadHeader(inFile)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.NewBuffer(header)
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../../test/sample.txt.enc")
	if err != nil {
		t.Error(err)
	}
	header1, err := NewHeader(inFile, readerSecretKey)
	if err != nil {
		t.Error(err)
	}
	header2, err := NewHeader(buffer, readerSecretKey)
	if err != nil {
		t.Error(err)
	}
	if fmt.Sprintf("%v", header1) != fmt.Sprintf("%v", header2) {
		t.Fail()
	}
}

func TestHeaderMarshallingWithoutNonce(t *testing.T) {

	writerPrivateKey, err := keys.ReadPrivateKey(strings.NewReader(sshEd25519SecEnc), []byte("123123"))
	if err != nil {
		t.Errorf("Reading private key from string failed: %v", err)
	}

	readerPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Errorf("Reading public key from string failed: %v", err)
	}
	magic := [8]byte{}
	copy(magic[:], MagicNumber)
	header := Header{
		MagicNumber:       magic,
		Version:           1,
		HeaderPacketCount: 2,
		HeaderPackets: []HeaderPacket{{
			WriterPrivateKey:       writerPrivateKey,
			ReaderPublicKey:        readerPublicKey,
			PacketLength:           10,
			HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
			EncryptedHeaderPacket: DataEncryptionParametersHeaderPacket{
				EncryptedSegmentSize: 10,
				PacketType:           PacketType{DataEncryptionParameters},
				DataEncryptionMethod: ChaCha20IETFPoly1305,
				DataKey:              [32]byte{},
			},
		},
			{
				WriterPrivateKey:       writerPrivateKey,
				ReaderPublicKey:        readerPublicKey,
				PacketLength:           10,
				HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
				EncryptedHeaderPacket: DataEditListHeaderPacket{
					PacketType:    PacketType{DataEditList},
					NumberLengths: 3,
					Lengths:       []uint64{1, 2, 3},
				},
			},
		},
	}
	marshalledHeader, err := header.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	if marshalledHeader == nil {
		t.Error(err)
	}
}

func TestHeader_GetDataEncryptionParameterHeaderPackets(t *testing.T) {
	header := Header{
		HeaderPackets: []HeaderPacket{
			{
				EncryptedHeaderPacket: DataEncryptionParametersHeaderPacket{
					EncryptedSegmentSize: 10,
					PacketType:           PacketType{DataEncryptionParameters},
					DataEncryptionMethod: ChaCha20IETFPoly1305,
					DataKey:              [32]byte{},
				},
			},
		},
	}
	packets, err := header.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		t.Error(err)
	}
	if len(*packets) != 1 {
		t.Fail()
	}
	packet := (*packets)[0]
	dataKey := [32]byte{}
	if packet.EncryptedSegmentSize != 10 ||
		packet.PacketType.PacketType != DataEncryptionParameters ||
		packet.DataEncryptionMethod != ChaCha20IETFPoly1305 ||
		!bytes.Equal(packet.DataKey[:], dataKey[:]) {
		t.Fail()
	}
}

func TestHeader_GetDataEditListHeaderPacket(t *testing.T) {
	header := Header{
		HeaderPackets: []HeaderPacket{
			{
				EncryptedHeaderPacket: DataEditListHeaderPacket{
					PacketType:    PacketType{DataEditList},
					NumberLengths: 2,
					Lengths:       []uint64{10, 100},
				},
			},
		},
	}
	packet := header.GetDataEditListHeaderPacket()
	if packet == nil {
		t.Fail()
	} else if packet.PacketType.PacketType != DataEditList ||
		packet.NumberLengths != 2 ||
		packet.Lengths[0] != 10 ||
		packet.Lengths[1] != 100 {
		t.Fail()
	}
}

func TestReEncryptedHeaderReplacementAndAddition(t *testing.T) {
	inFile, err := os.Open("../../test/sample.txt.enc")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	oldHeader, err := ReadHeader(inFile)
	if err != nil {
		t.Error(err)
	}

	newReaderPublicKey, err := keys.ReadPublicKey(strings.NewReader(newRecipientPub))
	if err != nil {
		t.Error(err)
	}
	newReaderPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	newReaderPublicKeyList = append(newReaderPublicKeyList, newReaderPublicKey)

	del := DataEditListHeaderPacket{PacketType: PacketType{DataEditList}, NumberLengths: 2, Lengths: []uint64{10, 100}}
	anotherDel := DataEditListHeaderPacket{PacketType: PacketType{DataEditList}, NumberLengths: 4, Lengths: []uint64{0, 5, 10, 15}}

	newHeader, err := ReEncryptHeader(oldHeader, readerSecretKey, newReaderPublicKeyList, del, anotherDel)
	if err != nil {
		t.Errorf("Reencrypting header gave unexpected failure: %v", err)
	}
	t.Logf("Header: %v", newHeader)

	// if the headers are similar then that is not ok
	if fmt.Sprintf("%v", oldHeader) == fmt.Sprintf("%v", newHeader) {
		t.Fail()
	}

	// check the header contents is what we expect
	newReaderSecretKey, err := keys.ReadPrivateKey(strings.NewReader(newRecipientSec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.NewBuffer(newHeader)
	header, err := NewHeader(buffer, newReaderSecretKey)
	if err != nil {
		t.Errorf("NewHeader gave unexpected failure: %v", err)
	}

	newDel, ok := header.HeaderPackets[1].EncryptedHeaderPacket.(DataEditListHeaderPacket)

	if !ok {
		t.Logf("Not DEL as expected: %v", header.HeaderPackets[1].EncryptedHeaderPacket)
		t.Fail()
	}

	if newDel.NumberLengths != 4 || !reflect.DeepEqual(newDel.Lengths, []uint64{0, 5, 10, 15}) {
		t.Logf("Unexpected length (%d vs 4) or content in overriden DEL: %v vs {0, 5, 10, 15}", newDel.NumberLengths, newDel.Lengths)
		t.Fail()
	}

	// Test DEL copying when reencryption, i.e. when the DEL is not replaced. Encrypt back for the original recipient

	newRecipientSecretKey, err := keys.ReadPrivateKey(strings.NewReader(newRecipientSec), []byte("password"))
	if err != nil {
		t.Errorf("Failed creating new recipient secret key: %v", err)
	}

	newerReaderPublicKey, err := keys.ReadPublicKey(strings.NewReader(crypt4ghX25519Pub))
	if err != nil {
		t.Error(err)
	}

	newerReaderPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	newerReaderPublicKeyList = append(newerReaderPublicKeyList, newerReaderPublicKey)

	newerHeader, err := ReEncryptHeader(newHeader, newRecipientSecretKey, newerReaderPublicKeyList)
	if err != nil {
		t.Errorf("Reencryption back to original recipient failed: %v", err)
	}

	buffer = bytes.NewBuffer(newerHeader)
	header, err = NewHeader(buffer, readerSecretKey)
	if err != nil {
		t.Errorf("NewHeader gave unexpected failure: %v", err)
	}

	newDel, ok = header.HeaderPackets[1].EncryptedHeaderPacket.(DataEditListHeaderPacket)
	if !ok {
		t.Logf("Not DEL as expected: %v", header.HeaderPackets[1].EncryptedHeaderPacket)
		t.Fail()
	}
	if newDel.NumberLengths != 4 || !reflect.DeepEqual(newDel.Lengths, []uint64{0, 5, 10, 15}) {
		t.Logf("Unexpected length (%d vs 4) or content in copied DEL: %v vs {0, 5, 10, 15}", newDel.NumberLengths, newDel.Lengths)
		t.Fail()
	}

}

func TestReEncryptedHeader(t *testing.T) {
	inFile, err := os.Open("../../test/sample.txt.enc")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	oldHeader, err := ReadHeader(inFile)
	if err != nil {
		t.Error(err)
	}

	newReaderPublicKey, err := keys.ReadPublicKey(strings.NewReader(newRecipientPub))
	if err != nil {
		t.Error(err)
	}
	newReaderPublicKeyList := [][chacha20poly1305.KeySize]byte{}
	newReaderPublicKeyList = append(newReaderPublicKeyList, newReaderPublicKey)

	newHeader, err := ReEncryptHeader(oldHeader, readerSecretKey, newReaderPublicKeyList)
	if err != nil {
		t.Errorf("ReEncryptHeader gave unexpected failure: %v", err)
	}

	// if the headers are similar then that is not ok
	if fmt.Sprintf("%v", oldHeader) == fmt.Sprintf("%v", newHeader) {
		t.Fail()
	}

	// check the header contents is what we expect
	newReaderSecretKey, err := keys.ReadPrivateKey(strings.NewReader(newRecipientSec), []byte("password"))
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.NewBuffer(newHeader)
	header, err := NewHeader(buffer, newReaderSecretKey)
	if err != nil {
		t.Errorf("NewHeader gave unexpected failure: %v", err)
	}
	if fmt.Sprintf("%v", header) != "&{[99 114 121 112 116 52 103 104] 1 1 [{[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] 108 0 <nil> {65564 {0} 0 [111 194 187 210 222 31 213 211 134 204 70 51 56 197 11 150 188 141 28 253 188 188 76 243 7 143 50 179 45 172 135 132]}}]}" {
		t.Error(header)
		t.Fail()
	}
}

func TestEncryptedSegmentSize(t *testing.T) {
	inFile, err := os.Open("../../test/sample.txt.enc")
	if err != nil {
		t.Errorf("Fileopen failed: %v", err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Errorf("ReadPrivateKey failed: %v", err)
	}

	header, err := ReadHeader(inFile)
	if err != nil {
		t.Errorf("ReadHeader failed: %v", err)
	}

	size, err := EncryptedSegmentSize(header, readerSecretKey)
	if err != nil {
		t.Errorf("EncryptedSegmentSize failed where it should work: %v", err)
	} else if size != 65564 {
		t.Errorf("EncryptedSegmentSize returned unexpected size %d (expected 65564)", size)
	}

	_, err = EncryptedSegmentSize(header, ([32]byte)(make([]byte, 32)))
	if err == nil {
		t.Errorf("EncryptedSegmentSize worked where it should fail: %v", err)
	}

	_, err = EncryptedSegmentSize(make([]byte, 2), readerSecretKey)
	if err == nil {
		t.Errorf("EncryptedSegmentSize worked where it should fail: %v", err)
	}
}

func TestHeaderLimits(t *testing.T) {

	// Test ReadHeader packet count limit
	b := bytes.NewBuffer([]byte("crypt4gh\x01\x00\x00\x00\x01\x00\x00\x11"))
	_, err := ReadHeader(b)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") || !strings.Contains(err.Error(), "count") {
		t.Errorf("Didn't see expected error from ReadHeader, expected header packet count, got %v", err)
	}

	// Test ReadHeader packet length limit
	b = bytes.NewBuffer([]byte("crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\x00\x00"))
	_, err = ReadHeader(b)

	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") || !strings.Contains(err.Error(), "length") {
		t.Errorf("Didn't see expected error from ReadHeader, expected header packet count, got %v", err)
	}

	// Test NewHeader packet count limit
	var key [chacha20poly1305.KeySize]byte
	b = bytes.NewBuffer([]byte("crypt4gh\x01\x00\x00\x00\x01\x00\x00\x11"))
	_, err = NewHeader(b, key)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") || !strings.Contains(err.Error(), "count") {
		t.Errorf("Didn't see expected error from ReadHeader, expected header packet count, got %v", err)
	}

	// Test NewHeader packet length limit
	b = bytes.NewBuffer([]byte("crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\x00\x00"))
	_, err = NewHeader(b, key)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") || !strings.Contains(err.Error(), "length") {
		t.Errorf("Didn't see expected error from ReadHeader, expected header packet count, got %v", err)
	}

}

func TestNewEncryptedHeaderPacketTooShort(t *testing.T) {
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	// A payload shorter than a writer public key, a nonce and the Poly1305 tag
	// was sliced without a length check, which panicked. It must now return an
	// error for every short length.
	for _, size := range []int{0, 8, 32, 43, 44, 59} {
		_, err := NewEncryptedHeaderPacket(make([]byte, size), readerSecretKey)
		if err == nil {
			t.Errorf("expected an error for a %d-byte payload, got nil", size)
		}
	}
}

func TestNewHeaderTruncatedPacket(t *testing.T) {
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	// A header that declares a single packet of length 8 (no payload) made the
	// reader slice an empty buffer and panic. It must return an error instead.
	// magic + version 1 + packet count 1 + packet{length 8, method 0}.
	malformed, err := hex.DecodeString("6372797074346768" + "01000000" + "01000000" + "08000000" + "00000000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHeader(bytes.NewReader(malformed), readerSecretKey); err == nil {
		t.Error("expected an error for a truncated header packet, got nil")
	}
}

func TestNewEncryptedHeaderPacketUnknownType(t *testing.T) {
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	readerPublicKey := keys.DerivePublicKey(readerSecretKey)
	writerPublicKey, writerSecretKey, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// A payload that decrypts cleanly but declares a packet type that is neither
	// DataEncryptionParameters (0) nor DataEditList (1). Without a default case
	// this left a nil interface and nil-dereferenced on the first method call.
	var unknownType [4]byte
	binary.LittleEndian.PutUint32(unknownType[:], 99)

	sharedKey, err := keys.GenerateWriterSharedKey(writerSecretKey, readerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(*sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, unknownType[:], nil)

	payload := make([]byte, 0, chacha20poly1305.KeySize+chacha20poly1305.NonceSize+len(sealed))
	payload = append(payload, writerPublicKey[:]...)
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	_, err = NewEncryptedHeaderPacket(payload, readerSecretKey)
	var unknownErr *UnknownHeaderPacketTypeError
	if !errors.As(err, &unknownErr) {
		t.Errorf("expected an UnknownHeaderPacketTypeError, got %v", err)
	}
}

// TestNewHeaderSkipsUnknownPacketType builds a header with one valid data
// encryption parameters packet and one packet of an unknown type, both
// encrypted to the reader. NewHeader must skip the unknown packet and return
// only the valid one, per the spec, rather than nil-dereferencing or failing
// the whole header.
func TestNewHeaderSkipsUnknownPacketType(t *testing.T) {
	readerPublicKey, readerSecretKey, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	writerPublicKey, writerSecretKey, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// valid data encryption parameters packet, marshalled by the library
	validPacket := HeaderPacket{
		WriterPrivateKey:       writerSecretKey,
		ReaderPublicKey:        readerPublicKey,
		HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
		EncryptedHeaderPacket: DataEncryptionParametersHeaderPacket{
			EncryptedSegmentSize: 65564,
			PacketType:           PacketType{DataEncryptionParameters},
			DataEncryptionMethod: ChaCha20IETFPoly1305,
			DataKey:              [32]byte{},
		},
	}
	validBytes, err := validPacket.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// unknown-type packet, hand-built so it decrypts but declares type 99
	sharedKey, err := keys.GenerateWriterSharedKey(writerSecretKey, readerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(*sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	var unknownType [4]byte
	binary.LittleEndian.PutUint32(unknownType[:], 99)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, unknownType[:], nil)
	body := make([]byte, 0, chacha20poly1305.KeySize+len(nonce)+len(sealed))
	body = append(body, writerPublicKey[:]...)
	body = append(body, nonce...)
	body = append(body, sealed...)
	var unknownBytes bytes.Buffer
	_ = binary.Write(&unknownBytes, binary.LittleEndian, uint32(4+4+len(body)))
	_ = binary.Write(&unknownBytes, binary.LittleEndian, X25519ChaCha20IETFPoly1305)
	unknownBytes.Write(body)

	var header bytes.Buffer
	header.WriteString(MagicNumber)
	_ = binary.Write(&header, binary.LittleEndian, Version)
	_ = binary.Write(&header, binary.LittleEndian, uint32(2)) // two packets
	header.Write(validBytes)
	header.Write(unknownBytes.Bytes())

	parsed, err := NewHeader(bytes.NewReader(header.Bytes()), readerSecretKey)
	if err != nil {
		t.Fatalf("NewHeader must skip the unknown packet, got error: %v", err)
	}
	if len(parsed.HeaderPackets) != 1 {
		t.Fatalf("expected 1 packet after skipping the unknown one, got %d", len(parsed.HeaderPackets))
	}
	if parsed.HeaderPackets[0].EncryptedHeaderPacket.GetPacketType() != DataEncryptionParameters {
		t.Errorf("expected the surviving packet to be DataEncryptionParameters")
	}
}

func TestNewHeaderPacketTooShortLength(t *testing.T) {
	readerSecretKey, err := keys.ReadPrivateKey(strings.NewReader(crypt4ghX25519Sec), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	// A PacketLength below the minimum must be rejected before make([]byte,
	// PacketLength-8), which would otherwise underflow the uint32 (lengths 4-7)
	// and request gigabytes. The 4-byte method is present so parsing would reach
	// make() without the guard; asserting the guard's own message, not just any
	// error, pins the guard instead of an incidental EOF.
	for _, length := range []uint32{0, 3, 4, 7, 67} {
		var packet bytes.Buffer
		_ = binary.Write(&packet, binary.LittleEndian, length)
		_ = binary.Write(&packet, binary.LittleEndian, X25519ChaCha20IETFPoly1305)
		_, err := NewHeaderPacket(bytes.NewReader(packet.Bytes()), readerSecretKey)
		if err == nil || !strings.Contains(err.Error(), "too short") {
			t.Errorf("expected a \"too short\" error for packet length %d, got %v", length, err)
		}
	}
}

func TestReadHeaderTooShortPacketLength(t *testing.T) {
	// ReadHeader must reject a short packet length before int64(packetLength-4)
	// underflows and io.CopyN copies the rest of the stream into memory.
	for _, length := range []uint32{0, 3, 4, 7, 67} {
		var header bytes.Buffer
		header.WriteString(MagicNumber)
		_ = binary.Write(&header, binary.LittleEndian, Version)
		_ = binary.Write(&header, binary.LittleEndian, uint32(1)) // one packet
		_ = binary.Write(&header, binary.LittleEndian, length)
		header.Write(make([]byte, 64)) // trailing bytes CopyN would grab without the guard
		_, err := ReadHeader(bytes.NewReader(header.Bytes()))
		if err == nil || !strings.Contains(err.Error(), "too short") {
			t.Errorf("expected a \"too short\" error for packet length %d, got %v", length, err)
		}
	}
}
