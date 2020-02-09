package headers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const MagicNumber string = "crypt4gh"
const Version1 uint32 = 1

type HeaderPacketType uint32

const (
	DataEncryptionParameters HeaderPacketType = iota
	DataEditList
)

type HeaderEncryptionMethod uint32

const (
	X25519ChaCha20IETFPoly1305 HeaderEncryptionMethod = iota
)

type DataEncryptionMethod uint32

const (
	ChaCha20IETFPoly1305 DataEncryptionMethod = iota
)

type Header struct {
	magicNumber       [8]byte
	version           uint32
	headerPacketCount uint32
	headerPackets     []HeaderPacket
}

func NewHeader(reader io.Reader) (*Header, error) {
	header := Header{}
	_, err := reader.Read(header.magicNumber[:])
	if err != nil {
		return nil, err
	}
	if string(header.magicNumber[:]) != MagicNumber {
		return nil, errors.New("not a Crypt4GH file")
	}
	err = binary.Read(reader, binary.LittleEndian, &header.version)
	if err != nil {
		return nil, err
	}
	if header.version != Version1 {
		return nil, errors.New(fmt.Sprintf("version %v not supported", header.version))
	}
	err = binary.Read(reader, binary.LittleEndian, &header.headerPacketCount)
	if err != nil {
		return nil, err
	}
	header.headerPackets = make([]HeaderPacket, 0)
	for i := uint32(0); i < header.headerPacketCount; i++ {
		headerPacket, err := NewHeaderPacket(reader)
		if err != nil {
			return nil, err
		}
		header.headerPackets = append(header.headerPackets, *headerPacket)
	}
	return &header, nil
}

type HeaderPacket struct {
	packetLength           uint32
	headerEncryptionMethod HeaderEncryptionMethod
	encryptedHeaderPacket  EncryptedHeaderPacket
}

func NewHeaderPacket(reader io.Reader) (*HeaderPacket, error) {
	var headerPacket HeaderPacket
	err := binary.Read(reader, binary.LittleEndian, &headerPacket.packetLength)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.LittleEndian, &headerPacket.headerEncryptionMethod)
	if err != nil {
		return nil, err
	}
	encryptedHeaderPacket, err := NewEncryptedHeaderPacket(reader)
	if err != nil {
		return nil, err
	}
	headerPacket.encryptedHeaderPacket = *encryptedHeaderPacket
	return &headerPacket, nil
}

type X25519ChaCha20IETFPoly1305HeaderPacket struct {
	HeaderPacket
	writerPublicKey [32]byte
	nonce           [12]byte
	mac             [16]byte
}

type EncryptedHeaderPacket interface {
	GetPacketType() HeaderPacketType
}

func NewEncryptedHeaderPacket(reader io.Reader) (*EncryptedHeaderPacket, error) {
	var encryptedHeaderPacket EncryptedHeaderPacket
	encryptedHeaderPacket = DataEncryptionParametersEncryptedHeaderPacket{}
	return &encryptedHeaderPacket, nil
}

type DataEncryptionParametersEncryptedHeaderPacket struct {
	dataEncryptionMethod DataEncryptionMethod
}

func (depehp DataEncryptionParametersEncryptedHeaderPacket) GetPacketType() HeaderPacketType {
	return DataEncryptionParameters
}

type ChaCha20IETFPoly1305DataEncryptionParametersEncryptedHeaderPacket struct {
	DataEncryptionParametersEncryptedHeaderPacket
	dataKey [32]byte
}

type DataEditListEncryptedHeaderPacket struct {
	numberLengths uint32
	lengths       []uint64
}

func (delehp DataEditListEncryptedHeaderPacket) GetPacketType() HeaderPacketType {
	return DataEditList
}
