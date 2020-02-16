package streaming

import (
	"../model/body"
	"../model/headers"
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type Crypt4GHWriter struct {
	writer io.Writer

	header                               headers.Header
	dataEncryptionParametersHeaderPacket headers.DataEncryptionParametersHeaderPacket
	buffer                               bytes.Buffer
}

func NewCrypt4GHWriter(writer io.Writer, writerPrivateKey [chacha20poly1305.KeySize]byte, readerPublicKey [chacha20poly1305.KeySize]byte, dataEditListHeaderPacket *headers.DataEditListHeaderPacket) (*Crypt4GHWriter, error) {
	crypt4GHWriter := Crypt4GHWriter{}
	var sharedKey [chacha20poly1305.KeySize]byte
	_, err := rand.Read(sharedKey[:])
	if err != nil {
		return nil, err
	}
	headerPackets := make([]headers.HeaderPacket, 0)
	crypt4GHWriter.dataEncryptionParametersHeaderPacket = headers.DataEncryptionParametersHeaderPacket{
		EncryptedSegmentSize: chacha20poly1305.NonceSize + headers.UnencryptedDataSegmentSize + box.Overhead,
		PacketType:           headers.PacketType{PacketType: headers.DataEncryptionParameters},
		DataEncryptionMethod: headers.ChaCha20IETFPoly1305,
		DataKey:              sharedKey,
	}
	headerPackets = append(headerPackets, headers.HeaderPacket{
		WriterPrivateKey:       writerPrivateKey,
		ReaderPublicKey:        readerPublicKey,
		HeaderEncryptionMethod: headers.X25519ChaCha20IETFPoly1305,
		EncryptedHeaderPacket:  crypt4GHWriter.dataEncryptionParametersHeaderPacket,
	})
	if dataEditListHeaderPacket != nil {
		headerPackets = append(headerPackets, headers.HeaderPacket{
			WriterPrivateKey:       writerPrivateKey,
			ReaderPublicKey:        readerPublicKey,
			HeaderEncryptionMethod: headers.X25519ChaCha20IETFPoly1305,
			EncryptedHeaderPacket:  dataEditListHeaderPacket,
		})
	}
	var magicNumber [8]byte
	copy(magicNumber[:], headers.MagicNumber)
	crypt4GHWriter.header = headers.Header{
		MagicNumber:       magicNumber,
		Version:           headers.Version1,
		HeaderPacketCount: 1,
		HeaderPackets:     headerPackets,
	}
	binaryHeader, err := crypt4GHWriter.header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	_, err = writer.Write(binaryHeader)
	if err != nil {
		return nil, err
	}
	crypt4GHWriter.writer = writer
	crypt4GHWriter.buffer.Grow(headers.UnencryptedDataSegmentSize)
	return &crypt4GHWriter, nil
}

func (c *Crypt4GHWriter) Write(p []byte) (n int, err error) {
	written := 0
	for ; written < len(p); written++ {
		if err := c.WriteByte(p[written]); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *Crypt4GHWriter) WriteByte(b byte) error {
	if c.buffer.Len() == c.buffer.Cap() {
		if err := c.flushBuffer(); err != nil {
			return err
		}
	}
	return c.buffer.WriteByte(b)
}

func (c *Crypt4GHWriter) Close() error {
	return c.flushBuffer()
}

func (c *Crypt4GHWriter) flushBuffer() error {
	segment := body.Segment{
		DataEncryptionParametersHeaderPackets: []headers.DataEncryptionParametersHeaderPacket{c.dataEncryptionParametersHeaderPacket},
		UnencryptedData:                       c.buffer.Bytes(),
	}
	c.buffer.Reset()
	marshalledSegment, err := segment.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = c.writer.Write(marshalledSegment)
	if err != nil {
		return err
	}
	return nil
}
