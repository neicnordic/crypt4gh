package body

import (
	"bytes"
	"encoding/hex"
	"testing"
)
import "../headers"

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
	if bytes.Compare(nonce[:], segment.UnencryptedData) != 0 {
		t.Fail()
	}
}
