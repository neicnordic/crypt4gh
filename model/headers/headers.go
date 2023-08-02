// Package headers contains structure and related methods for representing Crypt4GH header packets.
package headers

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/neicnordic/crypt4gh/keys"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

const (
	// MagicNumber is standard beginning of Crypt4GH header.
	MagicNumber string = "crypt4gh"

	// Version stands for current supported version.
	Version uint32 = 1

	// UnencryptedDataSegmentSize is the size of chunk of raw data.
	UnencryptedDataSegmentSize int = 65536
)

// HeaderPacketType is the enum listing possible header packet types.
type HeaderPacketType uint32

const (
	// DataEncryptionParameters is a packet type for data encryption parameters header packet.
	DataEncryptionParameters HeaderPacketType = iota

	// DataEditList is a packet type for data edit list header packet.
	DataEditList
)

// HeaderEncryptionMethod is the enum listing supported methods of encryption for header packets.
type HeaderEncryptionMethod uint32

const (
	// X25519ChaCha20IETFPoly1305 is header encryption method for X25519-ChaCha20-IETF-Poly1305.
	X25519ChaCha20IETFPoly1305 HeaderEncryptionMethod = iota
)

// DataEncryptionMethod is the enum listing supported methods of encryption for data segments.
type DataEncryptionMethod uint32

const (
	// ChaCha20IETFPoly1305 is header encryption method for ChaCha20-IETF-Poly1305.
	ChaCha20IETFPoly1305 DataEncryptionMethod = iota
)

// Header structure represents Crypt4GH header.
type Header struct {
	MagicNumber       [8]byte
	Version           uint32
	HeaderPacketCount uint32
	HeaderPackets     []HeaderPacket
}

type HeaderReaderError struct {
	ReaderPublicKey string
}

func (e *HeaderReaderError) Error() string {
	return fmt.Sprintf("could not decrypt header for key: %v", e.ReaderPublicKey)
}

// ReadHeader method strips off the header from the io.Reader and returns it as a byte array.
func ReadHeader(reader io.Reader) (header []byte, err error) {
	var magicNumber = [8]byte{}
	_, err = reader.Read(magicNumber[:])
	if err != nil {
		return
	}
	if string(magicNumber[:]) != MagicNumber {
		return header, errors.New("not a Crypt4GH file")
	}
	buffer := bytes.NewBuffer(magicNumber[:])
	var version uint32
	err = binary.Read(reader, binary.LittleEndian, &version)
	if err != nil {
		return
	}
	if version != Version {
		return header, fmt.Errorf("version %v not supported", version)
	}
	err = binary.Write(buffer, binary.LittleEndian, version)
	if err != nil {
		return
	}
	var headerPacketCount uint32
	err = binary.Read(reader, binary.LittleEndian, &headerPacketCount)
	if err != nil {
		return
	}
	err = binary.Write(buffer, binary.LittleEndian, headerPacketCount)
	if err != nil {
		return
	}
	for i := uint32(0); i < headerPacketCount; i++ {
		var packetLength uint32
		err = binary.Read(reader, binary.LittleEndian, &packetLength)
		if err != nil {
			return
		}
		err = binary.Write(buffer, binary.LittleEndian, packetLength)
		if err != nil {
			return
		}
		_, err = io.CopyN(buffer, reader, int64(packetLength-4)) // packetLength includes length of "packetLength"
		if err != nil {
			return
		}
	}

	return buffer.Bytes(), nil
}

// NewHeader method constructs Header from io.Reader and supplied private key.
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
	if header.Version != Version {
		return nil, fmt.Errorf("version %v not supported", header.Version)
	}
	err = binary.Read(reader, binary.LittleEndian, &header.HeaderPacketCount)
	if err != nil {
		return nil, err
	}
	header.HeaderPackets = make([]HeaderPacket, 0)
	for i := uint32(0); i < header.HeaderPacketCount; i++ {
		headerPacket, err := NewHeaderPacket(reader, readerPrivateKey)
		if err != nil {
			switch err := err.(type) {
			case *HeaderReaderError:
				// do nothing
				// we carry on and try the next header package
				continue
			default:
				// for any other error we return it
				return nil, err
			}
		}
		header.HeaderPackets = append(header.HeaderPackets, *headerPacket)
	}

	if len(header.HeaderPackets) == 0 {
		return nil, errors.New("could not find matching public key header, decryption failed")
	}

	return &header, nil
}

// GetDataEncryptionParameterHeaderPackets returns packets of type DataEncryptionParameterHeader.
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

// GetDataEditListHeaderPacket returns packet of type DataEditListHeaderPacket. Note that only one
// DataEditListHeaderPacket is returned - even if there are more in the Header.
func (h Header) GetDataEditListHeaderPacket() *DataEditListHeaderPacket {
	for _, headerPacket := range h.HeaderPackets {
		encryptedHeaderPacket := headerPacket.EncryptedHeaderPacket
		packetType := encryptedHeaderPacket.GetPacketType()
		if packetType == DataEditList {
			dataEditListHeaderPacket := encryptedHeaderPacket.(DataEditListHeaderPacket)

			return &dataEditListHeaderPacket
		}
	}

	return nil
}

// MarshalBinary implements method MarshalBinary.BinaryMarshaler.
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
	for i := range h.HeaderPackets {
		marshalledHeaderPacket, err := h.HeaderPackets[i].MarshalBinary()
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

// HeaderPacket structure represents Crypt4GH header packet.
type HeaderPacket struct {
	WriterPrivateKey       [chacha20poly1305.KeySize]byte
	ReaderPublicKey        [chacha20poly1305.KeySize]byte
	PacketLength           uint32
	HeaderEncryptionMethod HeaderEncryptionMethod
	Nonce                  *[chacha20poly1305.NonceSize]byte
	EncryptedHeaderPacket  EncryptedHeaderPacket
}

// NewHeaderPacket method constructs HeaderPacket from io.Reader and supplied private key.
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
	encryptedHeaderPacket, err := NewEncryptedHeaderPacket(encryptedPacketPayload, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	headerPacket.EncryptedHeaderPacket = *encryptedHeaderPacket

	return &headerPacket, nil
}

// MarshalBinary implements method MarshalBinary.BinaryMarshaler.
func (hp *HeaderPacket) MarshalBinary() (data []byte, err error) {
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
	default:
		return nil, fmt.Errorf("header encryption method not supported: %v", hp.HeaderEncryptionMethod)
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

// EncryptedHeaderPacket interface describes possible header packets: DataEncryptionParametersHeaderPacket and
// DataEditListHeaderPacket.
type EncryptedHeaderPacket interface {
	// GetPacketType method returns packet type of the header packet.
	GetPacketType() HeaderPacketType

	// MarshalBinary implements method MarshalBinary.BinaryMarshaler.
	MarshalBinary() (data []byte, err error)
}

// NewEncryptedHeaderPacket method constructs EncryptedHeaderPacket from io.Reader and supplied private key.
// headerEncryptionMethod HeaderEncryptionMethod was not used thus we remove it
func NewEncryptedHeaderPacket(encryptedPacketPayload []byte, readerPrivateKey [chacha20poly1305.KeySize]byte) (*EncryptedHeaderPacket, error) {
	var encryptedHeaderPacket EncryptedHeaderPacket
	// for headerEncryptionMethod we only support X25519ChaCha20IETFPoly1305
	// if we support more then we need to check for header
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
		// this means we can proceed to the next reader
		// if it still errors, then we cannot decrypt the file
		publicKey := keys.DerivePublicKey(readerPrivateKey)

		return nil, &HeaderReaderError{ReaderPublicKey: hex.EncodeToString(publicKey[:])}
	}
	decryptedPayloadReader := bytes.NewReader(decryptedPayload)
	var packetType HeaderPacketType
	err = binary.Read(decryptedPayloadReader, binary.LittleEndian, &packetType)
	if err != nil {
		return nil, err
	}
	switch packetType {
	case DataEncryptionParameters:
		packet, err := NewDataEncryptionParametersHeaderPacket(decryptedPayloadReader)
		if err != nil {
			return nil, err
		}
		encryptedHeaderPacket = *packet
	case DataEditList:
		packet, err := NewDataEditListHeaderPacket(decryptedPayloadReader)
		if err != nil {
			return nil, err
		}
		encryptedHeaderPacket = *packet
	}

	return &encryptedHeaderPacket, nil
}

// PacketType structure is a wrapper for HeaderPacketType.
type PacketType struct {
	PacketType HeaderPacketType
}

// GetPacketType method returns packet type of the header packet.
func (pth PacketType) GetPacketType() HeaderPacketType {
	return pth.PacketType
}

// DataEncryptionParametersHeaderPacket structure represents Crypt4GH data encryption parameters header packet.
type DataEncryptionParametersHeaderPacket struct {
	EncryptedSegmentSize int
	PacketType
	DataEncryptionMethod DataEncryptionMethod
	DataKey              [chacha20poly1305.KeySize]byte
}

// NewDataEncryptionParametersHeaderPacket method constructs DataEncryptionParametersHeaderPacket from io.Reader.
func NewDataEncryptionParametersHeaderPacket(reader io.Reader) (*DataEncryptionParametersHeaderPacket, error) {
	dataEncryptionParametersHeaderPacket := DataEncryptionParametersHeaderPacket{PacketType: PacketType{DataEncryptionParameters}}
	err := binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersHeaderPacket.DataEncryptionMethod)
	if err != nil {
		return nil, err
	}
	// we only use ChaCha20IETFPoly1305 for dataEncryptionParametersHeaderPacket.DataEncryptionMethod
	// thus we fix it
	dataEncryptionParametersHeaderPacket.EncryptedSegmentSize = chacha20poly1305.NonceSize + UnencryptedDataSegmentSize + box.Overhead
	err = binary.Read(reader, binary.LittleEndian, &dataEncryptionParametersHeaderPacket.DataKey)
	if err != nil {
		return nil, err
	}

	return &dataEncryptionParametersHeaderPacket, nil
}

// MarshalBinary implements method MarshalBinary.BinaryMarshaler.
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

// DataEditListHeaderPacket structure represents Crypt4GH data edit list header packet.
type DataEditListHeaderPacket struct {
	PacketType
	NumberLengths uint32
	Lengths       []uint64
}

// NewDataEditListHeaderPacket method constructs DataEditListHeaderPacket from io.Reader.
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

// MarshalBinary implements method MarshalBinary.BinaryMarshaler.
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

// ReEncryptHeader takes an old header, decrypts it and using a list of receivers public keys
// and re-encrypts the header for those keys while keeping the dataEditList packets
func ReEncryptHeader(oldHeader []byte, readerPrivateKey [chacha20poly1305.KeySize]byte, readerPublicKeyList [][chacha20poly1305.KeySize]byte) (newBinaryHeader []byte, err error) {

	buffer := bytes.NewBuffer(oldHeader)
	decryptedHeader, err := NewHeader(buffer, readerPrivateKey)
	if err != nil {
		return nil, err
	}

	dataEncryptionParametersHeaderPackets, err := decryptedHeader.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		return nil, err
	}
	dataEditList := decryptedHeader.GetDataEditListHeaderPacket()

	firstDataEncryptionParametersHeader := (*dataEncryptionParametersHeaderPackets)[0]
	for _, dataEncryptionParametersHeader := range *dataEncryptionParametersHeaderPackets {
		if dataEncryptionParametersHeader.GetPacketType() != firstDataEncryptionParametersHeader.GetPacketType() {
			return nil, fmt.Errorf("different data encryption methods are not supported")
		}
	}
	encryptedSegmentSize := firstDataEncryptionParametersHeader.EncryptedSegmentSize

	// Create the new encrypted header packet
	encHeaderPacket := DataEncryptionParametersHeaderPacket{
		EncryptedSegmentSize: encryptedSegmentSize,
		PacketType:           PacketType{PacketType: DataEncryptionParameters},
		DataEncryptionMethod: ChaCha20IETFPoly1305,
		DataKey:              firstDataEncryptionParametersHeader.DataKey,
	}

	headerPackets := make([]HeaderPacket, 0)

	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	for _, readerPublicKey := range readerPublicKeyList {
		headerPackets = append(headerPackets, HeaderPacket{
			WriterPrivateKey:       privateKey,
			ReaderPublicKey:        readerPublicKey,
			HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
			EncryptedHeaderPacket:  encHeaderPacket,
		})
		if dataEditList != nil {
			headerPackets = append(headerPackets, HeaderPacket{
				WriterPrivateKey:       privateKey,
				ReaderPublicKey:        readerPublicKey,
				HeaderEncryptionMethod: X25519ChaCha20IETFPoly1305,
				EncryptedHeaderPacket:  dataEditList,
			})
		}
	}

	var magicNumber [8]byte
	copy(magicNumber[:], MagicNumber)

	encHeader := Header{
		MagicNumber:       magicNumber,
		Version:           Version,
		HeaderPacketCount: uint32(len(headerPackets)),
		HeaderPackets:     headerPackets,
	}

	newBinaryHeader, err = encHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return newBinaryHeader, nil
}
