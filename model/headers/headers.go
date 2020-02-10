package headers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

import "../../keys"

const MagicNumber string = "crypt4gh"
const Version1 uint32 = 1
const UnencryptedDataSegmentSize = 65536

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
	MagicNumber       [8]byte
	Version           uint32
	HeaderPacketCount uint32
	HeaderPackets     []HeaderPacket
}

func (h Header) GetDataEncryptionParameterHeaderPackets() (*[]DataEncryptionParametersHeaderPacket, error) {
	dataEncryptionParametersHeaderPackets := make([]DataEncryptionParametersHeaderPacket, 0)
	for _, headerPacket := range h.HeaderPackets {
		encryptedHeaderPacket := headerPacket.encryptedHeaderPacket
		packetType := encryptedHeaderPacket.GetPacketType()
		if packetType == DataEncryptionParameters {
			dataEncryptionParametersHeaderPackets = append(dataEncryptionParametersHeaderPackets, encryptedHeaderPacket.(DataEncryptionParametersHeaderPacket))
		}
	}
	if len(dataEncryptionParametersHeaderPackets) == 0 {
		return nil, errors.New("data encryption parameters not found in the header")
	}
	return &dataEncryptionParametersHeaderPackets, nil
}

func NewHeader(reader io.Reader, readerPrivateKey [32]byte) (*Header, error) {
	header := Header{}
	_, err := reader.Read(header.MagicNumber[:])
	if err != nil {
		return nil, err
	}
	if string(header.MagicNumber[:]) != MagicNumber {
		return nil, errors.New("not a Crypt4GH file")
	}
	err = binary.Read(reader, binary.LittleEndian, &header.Version)
	if err != nil {
		return nil, err
	}
	if header.Version != Version1 {
		return nil, errors.New(fmt.Sprintf("version %v not supported", header.Version))
	}
	err = binary.Read(reader, binary.LittleEndian, &header.HeaderPacketCount)
	if err != nil {
		return nil, err
	}
	header.HeaderPackets = make([]HeaderPacket, 0)
	for i := uint32(0); i < header.HeaderPacketCount; i++ {
		headerPacket, err := NewHeaderPacket(reader, readerPrivateKey)
		if err != nil {
			return nil, err
		}
		header.HeaderPackets = append(header.HeaderPackets, *headerPacket)
	}
	return &header, nil
}

type HeaderPacket struct {
	packetLength           uint32
	headerEncryptionMethod HeaderEncryptionMethod
	encryptedHeaderPacket  EncryptedHeaderPacket
}

func NewHeaderPacket(reader io.Reader, readerPrivateKey [32]byte) (*HeaderPacket, error) {
	var headerPacket HeaderPacket
	err := binary.Read(reader, binary.LittleEndian, &headerPacket.packetLength)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.LittleEndian, &headerPacket.headerEncryptionMethod)
	if err != nil {
		return nil, err
	}
	encryptedPacketPayload := make([]byte, headerPacket.packetLength-4-4)
	err = binary.Read(reader, binary.LittleEndian, &encryptedPacketPayload)
	if err != nil {
		return nil, err
	}
	encryptedHeaderPacket, err := NewEncryptedHeaderPacket(encryptedPacketPayload, headerPacket.headerEncryptionMethod, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	headerPacket.encryptedHeaderPacket = *encryptedHeaderPacket
	return &headerPacket, nil
}

type EncryptedHeaderPacket interface {
	GetPacketType() HeaderPacketType
}

func NewEncryptedHeaderPacket(encryptedPacketPayload []byte, headerEncryptionMethod HeaderEncryptionMethod, readerPrivateKey [32]byte) (*EncryptedHeaderPacket, error) {
	var encryptedHeaderPacket EncryptedHeaderPacket
	switch headerEncryptionMethod {
	case X25519ChaCha20IETFPoly1305:
		var writerPublicKeyBytes [32]byte
		copy(writerPublicKeyBytes[:], encryptedPacketPayload[:chacha20poly1305.KeySize])
		nonce := encryptedPacketPayload[chacha20poly1305.KeySize : chacha20poly1305.KeySize+chacha20poly1305.NonceSize]
		encryptedPayload := encryptedPacketPayload[chacha20poly1305.KeySize+chacha20poly1305.NonceSize:]
		sharedKey, err := keys.GenerateReaderSharedKey(readerPrivateKey, writerPublicKeyBytes)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(*sharedKey)
		if err != nil {
			return nil, err
		}
		decryptedPayload, err := aead.Open(nil, nonce, encryptedPayload, nil)
		if err != nil {
			return nil, err
		}
		decryptedPayloadReader := bytes.NewReader(decryptedPayload)
		var packetType HeaderPacketType
		err = binary.Read(decryptedPayloadReader, binary.LittleEndian, &packetType)
		switch packetType {
		case DataEncryptionParameters:
			packet, err := NewDataEncryptionParametersHeaderPacket(decryptedPayloadReader)
			if err != nil {
				return nil, err
			}
			encryptedHeaderPacket = *packet
			break
		case DataEditList:
			packet, err := NewDataEditListHeaderPacket(decryptedPayloadReader)
			if err != nil {
				return nil, err
			}
			encryptedHeaderPacket = *packet
			break
		}
		break
	}

	return &encryptedHeaderPacket, nil
}

type DataEncryptionParametersHeaderPacket struct {
	EncryptedSegmentSize int
	DataEncryptionMethod DataEncryptionMethod
	DataKey              [32]byte
}

func NewDataEncryptionParametersHeaderPacket(reader io.Reader) (*DataEncryptionParametersHeaderPacket, error) {
	dataEncryptionParametersHeaderPacket := DataEncryptionParametersHeaderPacket{EncryptedSegmentSize: chacha20poly1305.NonceSize + UnencryptedDataSegmentSize + 16}
	err := binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersHeaderPacket.DataEncryptionMethod)
	if err != nil {
		return nil, err
	}
	switch dataEncryptionParametersHeaderPacket.DataEncryptionMethod {
	case ChaCha20IETFPoly1305:
		err := binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersHeaderPacket.DataKey)
		if err != nil {
			return nil, err
		}
		break
	}
	return &dataEncryptionParametersHeaderPacket, nil
}

func (dephp DataEncryptionParametersHeaderPacket) GetPacketType() HeaderPacketType {
	return DataEncryptionParameters
}

type DataEditListHeaderPacket struct {
	numberLengths uint32
	lengths       []uint64
}

func NewDataEditListHeaderPacket(reader io.Reader) (*DataEditListHeaderPacket, error) {
	dataEditListHeaderPacket := DataEditListHeaderPacket{}
	err := binary.Read(reader, binary.LittleEndian, &dataEditListHeaderPacket.numberLengths)
	if err != nil {
		return nil, err
	}
	dataEditListHeaderPacket.lengths = make([]uint64, 0)
	for i := uint32(0); i < dataEditListHeaderPacket.numberLengths; i++ {
		var length uint64
		err := binary.Read(reader, binary.LittleEndian, &length)
		if err != nil {
			return nil, err
		}
		dataEditListHeaderPacket.lengths = append(dataEditListHeaderPacket.lengths, length)
	}
	return &dataEditListHeaderPacket, nil
}

func (delhp DataEditListHeaderPacket) GetPacketType() HeaderPacketType {
	return DataEditList
}
