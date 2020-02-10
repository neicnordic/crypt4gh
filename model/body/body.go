package body

import (
	"../headers"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
)

type Segment struct {
	UnencryptedData []byte
}

func NewSegment(encryptedSegment []byte, dataEncryptionParametersHeaderPackets []headers.DataEncryptionParametersHeaderPacket) (*Segment, error) {
	segment := Segment{}
	for _, dataEncryptionParametersHeaderPacket := range dataEncryptionParametersHeaderPackets {
		switch dataEncryptionParametersHeaderPacket.DataEncryptionMethod {
		case headers.ChaCha20IETFPoly1305:
			dataKey := dataEncryptionParametersHeaderPacket.DataKey[:]
			aead, err := chacha20poly1305.New(dataKey)
			if err != nil {
				return nil, err
			}
			nonce := encryptedSegment[:chacha20poly1305.NonceSize]
			encryptedData := encryptedSegment[chacha20poly1305.NonceSize:]
			decryptedSegment, err := aead.Open(nil, nonce, encryptedData, nil)
			if err == nil {
				segment.UnencryptedData = decryptedSegment
				return &segment, nil
			}
			break
		}
	}
	return nil, errors.New("data segment can't be decrypted with any of header keys")
}
