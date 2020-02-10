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

func NewHeader(reader io.Reader, readerPrivateKey [32]byte) (*Header, error) {
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
		headerPacket, err := NewHeaderPacket(reader, readerPrivateKey)
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
			packet, err := NewDataEncryptionParametersEncryptedHeaderPacket(decryptedPayloadReader)
			if err != nil {
				return nil, err
			}
			encryptedHeaderPacket = *packet
			break
		case DataEditList:
			packet, err := NewDataEditListEncryptedHeaderPacket(decryptedPayloadReader)
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

type DataEncryptionParametersEncryptedHeaderPacket struct {
	dataKey [32]byte
}

func NewDataEncryptionParametersEncryptedHeaderPacket(reader io.Reader) (*DataEncryptionParametersEncryptedHeaderPacket, error) {
	dataEncryptionParametersEncryptedHeaderPacket := DataEncryptionParametersEncryptedHeaderPacket{}
	var dataEncryptionMethod DataEncryptionMethod
	err := binary.Read(reader, binary.LittleEndian, &dataEncryptionMethod)
	if err != nil {
		return nil, err
	}
	switch dataEncryptionMethod {
	case ChaCha20IETFPoly1305:
		err := binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersEncryptedHeaderPacket.dataKey)
		if err != nil {
			return nil, err
		}
		break
	}
	return &dataEncryptionParametersEncryptedHeaderPacket, nil
}

func (depehp DataEncryptionParametersEncryptedHeaderPacket) GetPacketType() HeaderPacketType {
	return DataEncryptionParameters
}

type DataEditListEncryptedHeaderPacket struct {
	numberLengths uint32
	lengths       []uint64
}

func NewDataEditListEncryptedHeaderPacket(reader io.Reader) (*DataEditListEncryptedHeaderPacket, error) {
	dataEditListEncryptedHeaderPacket := DataEditListEncryptedHeaderPacket{}
	err := binary.Read(reader, binary.LittleEndian, &dataEditListEncryptedHeaderPacket.numberLengths)
	if err != nil {
		return nil, err
	}
	dataEditListEncryptedHeaderPacket.lengths = make([]uint64, 0)
	for i := uint32(0); i < dataEditListEncryptedHeaderPacket.numberLengths; i++ {
		var length uint64
		err := binary.Read(reader, binary.LittleEndian, &length)
		if err != nil {
			return nil, err
		}
		dataEditListEncryptedHeaderPacket.lengths = append(dataEditListEncryptedHeaderPacket.lengths, length)
	}
	return &dataEditListEncryptedHeaderPacket, nil
}

func (delehp DataEditListEncryptedHeaderPacket) GetPacketType() HeaderPacketType {
	return DataEditList
}
