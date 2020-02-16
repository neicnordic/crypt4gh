package headers

import (
	"../../keys"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestHeaderMarshalling(t *testing.T) {
	keyFile, err := os.Open("../../test/ssh-ed25519-enc.sec.pem")
	if err != nil {
		panic(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(keyFile, []byte("123123"))
	if err != nil {
		panic(err)
	}
	keyFile, err = os.Open("../../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		panic(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(keyFile)
	if err != nil {
		panic(err)
	}
	var nonce = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	magic := [8]byte{}
	copy(magic[:], MagicNumber)
	header := Header{
		MagicNumber:       magic,
		Version:           1,
		HeaderPacketCount: 1,
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
		},
	}
	marshalledHeader, err := header.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(marshalledHeader) != "637279707434676801000000010000006c000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b0102030405060708090a0b0c8f5854ea6eceff229d474a1f35af0c7b9813ccc1ff370a56a630018203f102d99e83bd6e6cad47cc6d8185d1fa9ea800aedad79f47042ca3" {
		t.Fail()
	}
}

func TestNewHeader(t *testing.T) {
	decodedHeader, err := hex.DecodeString("637279707434676801000000010000006c000000000000005ee4b32a4b0fb53dc04dcb02aea9d258afd07736e13522ccaaf4077e643c8d1b0102030405060708090a0b0c8f5854ea6eceff229d474a1f35af0c7b9813ccc1ff370a56a630018203f102d99e83bd6e6cad47cc6d8185d1fa9ea800aedad79f47042ca3")
	if err != nil {
		t.Error(err)
	}
	buf := bytes.Buffer{}
	_, err = buf.Write(decodedHeader)
	if err != nil {
		t.Error(err)
	}
	keyFile, err := os.Open("../../test/crypt4gh-x25519-enc.sec.pem")
	if err != nil {
		panic(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(keyFile, []byte("password"))
	if err != nil {
		panic(err)
	}
	header, err := NewHeader(&buf, readerSecretKey)
	if err != nil {
		panic(err)
	}
	if fmt.Sprintf("%v", header) != "&{[99 114 121 112 116 52 103 104] 1 1 [{[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] 108 0 <nil> {65564 {0} 0 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}}]}" {
		t.Fail()
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
		bytes.Compare(packet.DataKey[:], dataKey[:]) != 0 {
		t.Fail()
	}
}
