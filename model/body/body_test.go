package body

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
)

var dataEncryptionParametersHeaderPacket = headers.DataEncryptionParametersHeaderPacket{
	PacketType:           headers.PacketType{PacketType: headers.DataEncryptionParameters},
	DataEncryptionMethod: headers.ChaCha20IETFPoly1305,
	DataKey:              [32]byte{},
}

var nonce = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

func TestSegment_MarshalBinaryWithNonce(t *testing.T) {

	segment := Segment{
		DataEncryptionParametersHeaderPackets: []headers.DataEncryptionParametersHeaderPacket{dataEncryptionParametersHeaderPacket},
		Nonce:                                 &nonce,
		UnencryptedData:                       nonce[:],
	}
	binary, err := segment.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(binary) != "0102030405060708090a0b0cf2cc363c27248a881b102cd36f678e1d88c47076e0d263ad45759c03" {
		t.Fail()
	}
}

func TestSegment_MarshalBinaryWithoutNonce(t *testing.T) {
	segment := Segment{
		DataEncryptionParametersHeaderPackets: []headers.DataEncryptionParametersHeaderPacket{dataEncryptionParametersHeaderPacket},
		UnencryptedData:                       nonce[:],
	}
	binary, err := segment.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	if binary == nil {
		t.Fail()
	}
}

func TestSegment_UnmarshalBinary(t *testing.T) {
	data, err := hex.DecodeString("0102030405060708090a0b0cf2cc363c27248a881b102cd36f678e1d88c47076e0d263ad45759c03")
	if err != nil {
		t.Error(err)
	}
	segment := Segment{
		DataEncryptionParametersHeaderPackets: []headers.DataEncryptionParametersHeaderPacket{dataEncryptionParametersHeaderPacket},
		Nonce:                                 &nonce,
	}
	err = segment.UnmarshalBinary(data)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(nonce[:], segment.UnencryptedData) {
		t.Fail()
	}
}

func TestSegment_UnmarshalBinaryTooShort(t *testing.T) {
	segment := Segment{
		DataEncryptionParametersHeaderPackets: []headers.DataEncryptionParametersHeaderPacket{dataEncryptionParametersHeaderPacket},
	}
	// A stream truncated 1-27 bytes into a segment must return an error, not
	// panic on slicing the nonce out of the buffer.
	for _, size := range []int{0, 1, 5, 11, 12, 27} {
		err := segment.UnmarshalBinary(make([]byte, size))
		if err == nil {
			t.Errorf("expected an error for a %d-byte segment, got nil", size)
		}
	}
}

func TestSegment_UnmarshalBinaryMinimumValidSegment(t *testing.T) {
	// A segment carrying an empty payload is a nonce plus the Poly1305 tag,
	// exactly NonceSize+Overhead bytes. It must decrypt, not be rejected as too
	// short; this guards the length check against a future < -> <= regression.
	aead, err := chacha20poly1305.New(dataEncryptionParametersHeaderPacket.DataKey[:])
	if err != nil {
		t.Fatal(err)
	}
	segmentNonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(segmentNonce); err != nil {
		t.Fatal(err)
	}
	encryptedSegment := make([]byte, 0, chacha20poly1305.NonceSize+chacha20poly1305.Overhead)
	encryptedSegment = append(encryptedSegment, segmentNonce...)
	encryptedSegment = append(encryptedSegment, aead.Seal(nil, segmentNonce, nil, nil)...)
	if len(encryptedSegment) != chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		t.Fatalf("expected a %d-byte segment, got %d", chacha20poly1305.NonceSize+chacha20poly1305.Overhead, len(encryptedSegment))
	}

	segment := Segment{
		DataEncryptionParametersHeaderPackets: []headers.DataEncryptionParametersHeaderPacket{dataEncryptionParametersHeaderPacket},
	}
	if err := segment.UnmarshalBinary(encryptedSegment); err != nil {
		t.Errorf("a minimum-size valid segment must decrypt, got error: %v", err)
	}
	if len(segment.UnencryptedData) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(segment.UnencryptedData))
	}
}
