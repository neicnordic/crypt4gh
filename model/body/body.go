package body

import (
	"../headers"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

type Segment struct {
	DataEncryptionParametersHeaderPackets []headers.DataEncryptionParametersHeaderPacket
	Nonce                                 [chacha20poly1305.NonceSize]byte
	UnencryptedData                       []byte
}

func (s Segment) MarshalBinary() (data []byte, err error) {
	dataEncryptionParametersHeaderPacket := s.DataEncryptionParametersHeaderPackets[0]
	switch dataEncryptionParametersHeaderPacket.DataEncryptionMethod {
	case headers.ChaCha20IETFPoly1305:
		dataKey := dataEncryptionParametersHeaderPacket.DataKey[:]
		_, err = rand.Read(s.Nonce[:])
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(dataKey)
		if err != nil {
			return nil, err
		}
		encryptedData := aead.Seal(nil, s.Nonce[:], s.UnencryptedData, nil)
		return append(s.Nonce[:], encryptedData...), nil
	}
	return nil, errors.New(fmt.Sprintf("unknown data encryption method: %v", dataEncryptionParametersHeaderPacket.DataEncryptionMethod))
}

func (s *Segment) UnmarshalBinary(encryptedSegment []byte) error {
	for _, dataEncryptionParametersHeaderPacket := range s.DataEncryptionParametersHeaderPackets {
		switch dataEncryptionParametersHeaderPacket.DataEncryptionMethod {
		case headers.ChaCha20IETFPoly1305:
			dataKey := dataEncryptionParametersHeaderPacket.DataKey[:]
			aead, err := chacha20poly1305.New(dataKey)
			if err != nil {
				return err
			}
			copy(s.Nonce[:], encryptedSegment[:chacha20poly1305.NonceSize])
			encryptedData := encryptedSegment[chacha20poly1305.NonceSize:]
			decryptedSegment, err := aead.Open(nil, s.Nonce[:], encryptedData, nil)
			if err == nil {
				s.UnencryptedData = decryptedSegment
				return nil
			}
			break
		}
	}
	return errors.New("data segment can't be decrypted with any of header keys")
}
