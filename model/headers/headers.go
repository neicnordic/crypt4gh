package headers

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
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

func NewHeader(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte) (*Header, error) {
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

func (h Header) GetDataEncryptionParameterHeaderPackets() (*[]DataEncryptionParametersHeaderPacket, error) {
	dataEncryptionParametersHeaderPackets := make([]DataEncryptionParametersHeaderPacket, 0)
	for _, headerPacket := range h.HeaderPackets {
		encryptedHeaderPacket := headerPacket.EncryptedHeaderPacket
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

func (h Header) MarshalBinary() (data []byte, err error) {
	buffer := bytes.Buffer{}
	err = binary.Write(&buffer, binary.LittleEndian, h.MagicNumber)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, h.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, h.HeaderPacketCount)
	if err != nil {
		return nil, err
	}
	for _, headerPacket := range h.HeaderPackets {
		marshalledHeaderPacket, err := headerPacket.MarshalBinary()
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buffer, binary.LittleEndian, marshalledHeaderPacket)
		if err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

type HeaderPacket struct {
	WriterPrivateKey       [chacha20poly1305.KeySize]byte
	ReaderPublicKey        [chacha20poly1305.KeySize]byte
	PacketLength           uint32
	HeaderEncryptionMethod HeaderEncryptionMethod
	Nonce                  *[chacha20poly1305.NonceSize]byte
	EncryptedHeaderPacket  EncryptedHeaderPacket
}

func NewHeaderPacket(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte) (*HeaderPacket, error) {
	var headerPacket HeaderPacket
	err := binary.Read(reader, binary.LittleEndian, &headerPacket.PacketLength)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.LittleEndian, &headerPacket.HeaderEncryptionMethod)
	if err != nil {
		return nil, err
	}
	encryptedPacketPayload := make([]byte, headerPacket.PacketLength-4-4)
	err = binary.Read(reader, binary.LittleEndian, &encryptedPacketPayload)
	if err != nil {
		return nil, err
	}
	encryptedHeaderPacket, err := NewEncryptedHeaderPacket(encryptedPacketPayload, headerPacket.HeaderEncryptionMethod, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	headerPacket.EncryptedHeaderPacket = *encryptedHeaderPacket
	return &headerPacket, nil
}

func (hp HeaderPacket) MarshalBinary() (data []byte, err error) {
	var encryptedMarshalledEncryptedHeaderPacket []byte
	switch hp.HeaderEncryptionMethod {
	case X25519ChaCha20IETFPoly1305:
		if hp.Nonce == nil {
			hp.Nonce = new([chacha20poly1305.NonceSize]byte)
			_, err = rand.Read(hp.Nonce[:])
			if err != nil {
				return nil, err
			}
		}

		marshalledEncryptedHeaderPacket, err := hp.EncryptedHeaderPacket.MarshalBinary()
		if err != nil {
			return nil, err
		}
		sharedKey, err := keys.GenerateWriterSharedKey(hp.WriterPrivateKey, hp.ReaderPublicKey)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(*sharedKey)
		if err != nil {
			return nil, err
		}
		encryptedMarshalledEncryptedHeaderPacket = aead.Seal(nil, hp.Nonce[:], marshalledEncryptedHeaderPacket, nil)
		break
	default:
		return nil, errors.New(fmt.Sprintf("header encryption method not supported: %v", hp.HeaderEncryptionMethod))
	}
	hp.PacketLength = uint32(4 + // hp.PacketLength field size
		4 + // hp.HeaderEncryptionMethod field size
		chacha20poly1305.KeySize +
		chacha20poly1305.NonceSize +
		len(encryptedMarshalledEncryptedHeaderPacket))
	buffer := bytes.Buffer{}
	err = binary.Write(&buffer, binary.LittleEndian, hp.PacketLength)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, hp.HeaderEncryptionMethod)
	if err != nil {
		return nil, err
	}
	writerPublicKey := keys.DerivePublicKey(hp.WriterPrivateKey)
	err = binary.Write(&buffer, binary.LittleEndian, writerPublicKey)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, hp.Nonce)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, encryptedMarshalledEncryptedHeaderPacket)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type EncryptedHeaderPacket interface {
	GetPacketType() HeaderPacketType
	MarshalBinary() (data []byte, err error)
}

func NewEncryptedHeaderPacket(encryptedPacketPayload []byte, headerEncryptionMethod HeaderEncryptionMethod, readerPrivateKey [chacha20poly1305.KeySize]byte) (*EncryptedHeaderPacket, error) {
	var encryptedHeaderPacket EncryptedHeaderPacket
	switch headerEncryptionMethod {
	case X25519ChaCha20IETFPoly1305:
		var writerPublicKeyBytes [chacha20poly1305.KeySize]byte
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

type PacketType struct {
	PacketType HeaderPacketType
}

func (pth PacketType) GetPacketType() HeaderPacketType {
	return pth.PacketType
}

type DataEncryptionParametersHeaderPacket struct {
	EncryptedSegmentSize int
	PacketType
	DataEncryptionMethod DataEncryptionMethod
	DataKey              [chacha20poly1305.KeySize]byte
}

func NewDataEncryptionParametersHeaderPacket(reader io.Reader) (*DataEncryptionParametersHeaderPacket, error) {
	dataEncryptionParametersHeaderPacket := DataEncryptionParametersHeaderPacket{PacketType: PacketType{DataEncryptionParameters}}
	err := binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersHeaderPacket.DataEncryptionMethod)
	if err != nil {
		return nil, err
	}
	switch dataEncryptionParametersHeaderPacket.DataEncryptionMethod {
	case ChaCha20IETFPoly1305:
		dataEncryptionParametersHeaderPacket.EncryptedSegmentSize = chacha20poly1305.NonceSize + UnencryptedDataSegmentSize + box.Overhead
		err := binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersHeaderPacket.DataKey)
		if err != nil {
			return nil, err
		}
		break
	}
	return &dataEncryptionParametersHeaderPacket, nil
}

func (dephp DataEncryptionParametersHeaderPacket) MarshalBinary() (data []byte, err error) {
	buffer := bytes.Buffer{}
	err = binary.Write(&buffer, binary.LittleEndian, dephp.PacketType)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, dephp.DataEncryptionMethod)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, dephp.DataKey)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type DataEditListHeaderPacket struct {
	PacketType
	NumberLengths uint32
	Lengths       []uint64
}

func NewDataEditListHeaderPacket(reader io.Reader) (*DataEditListHeaderPacket, error) {
	dataEditListHeaderPacket := DataEditListHeaderPacket{PacketType: PacketType{DataEditList}}
	err := binary.Read(reader, binary.LittleEndian, &dataEditListHeaderPacket.NumberLengths)
	if err != nil {
		return nil, err
	}
	dataEditListHeaderPacket.Lengths = make([]uint64, 0)
	for i := uint32(0); i < dataEditListHeaderPacket.NumberLengths; i++ {
		var length uint64
		err := binary.Read(reader, binary.LittleEndian, &length)
		if err != nil {
			return nil, err
		}
		dataEditListHeaderPacket.Lengths = append(dataEditListHeaderPacket.Lengths, length)
	}
	return &dataEditListHeaderPacket, nil
}

func (delhp DataEditListHeaderPacket) MarshalBinary() (data []byte, err error) {
	buffer := bytes.Buffer{}
	err = binary.Write(&buffer, binary.LittleEndian, delhp.PacketType)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, delhp.NumberLengths)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.LittleEndian, delhp.Lengths)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
