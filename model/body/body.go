// Package body contains structure and related methods for representing Crypt4GH data segments.
package body

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
)

// Segment structure represents Crypt4GH data segment.
type Segment struct {
	DataEncryptionParametersHeaderPackets []headers.DataEncryptionParametersHeaderPacket
	Nonce                                 *[chacha20poly1305.NonceSize]byte
	UnencryptedData                       []byte
}

// MarshalBinary implements encoding.BinaryMarshaler.MarshalBinary() method.
func (s *Segment) MarshalBinary() (data []byte, err error) {
	dataEncryptionParametersHeaderPacket := s.DataEncryptionParametersHeaderPackets[0]
	if dataEncryptionParametersHeaderPacket.DataEncryptionMethod == headers.ChaCha20IETFPoly1305 {
		dataKey := dataEncryptionParametersHeaderPacket.DataKey[:]
		if s.Nonce == nil {
			s.Nonce = new([chacha20poly1305.NonceSize]byte)
			_, err = rand.Read(s.Nonce[:])
			if err != nil {
				return nil, err
			}
		}
		aead, err := chacha20poly1305.New(dataKey)
		if err != nil {
			return nil, err
		}
		encryptedData := aead.Seal(nil, s.Nonce[:], s.UnencryptedData, nil)

		return append(s.Nonce[:], encryptedData...), nil
	}

	return nil, fmt.Errorf("unknown data encryption method: %v", dataEncryptionParametersHeaderPacket.DataEncryptionMethod)
}

// UnmarshalBinary implements encoding.BinaryMarshaler.UnmarshalBinary() method.
func (s *Segment) UnmarshalBinary(encryptedSegment []byte) error {
	for _, dataEncryptionParametersHeaderPacket := range s.DataEncryptionParametersHeaderPackets {
		if dataEncryptionParametersHeaderPacket.DataEncryptionMethod == headers.ChaCha20IETFPoly1305 {
			dataKey := dataEncryptionParametersHeaderPacket.DataKey[:]
			aead, err := chacha20poly1305.New(dataKey)
			if err != nil {
				return err
			}
			s.Nonce = new([chacha20poly1305.NonceSize]byte)
			copy(s.Nonce[:], encryptedSegment[:chacha20poly1305.NonceSize])
			encryptedData := encryptedSegment[chacha20poly1305.NonceSize:]
			decryptedSegment, err := aead.Open(nil, s.Nonce[:], encryptedData, nil)
			if err == nil {
				s.UnencryptedData = decryptedSegment

				return nil
			}
		}
	}

	return errors.New("data segment can't be decrypted with any of header keys")
}
