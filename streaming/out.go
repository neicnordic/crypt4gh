// Package streaming contains writer and reader implementing Crypt4GH encryption and decryption correspondingly.
package streaming

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/body"
	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

// Crypt4GHWriter structure implements io.WriteCloser and io.ByteWriter.
type Crypt4GHWriter struct {
	writer io.Writer

	header                               headers.Header
	dataEncryptionParametersHeaderPacket headers.DataEncryptionParametersHeaderPacket
	buffer                               bytes.Buffer
}

// NewCrypt4GHWriter method constructs streaming.Crypt4GHWriter instance from io.Writer and corresponding keys.
func NewCrypt4GHWriter(writer io.Writer, writerPrivateKey [chacha20poly1305.KeySize]byte, readerPublicKeyList [][chacha20poly1305.KeySize]byte, dataEditList *headers.DataEditListHeaderPacket) (*Crypt4GHWriter, error) {
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

	for _, readerPublicKey := range readerPublicKeyList {
		headerPackets = append(headerPackets, headers.HeaderPacket{
			WriterPrivateKey:       writerPrivateKey,
			ReaderPublicKey:        readerPublicKey,
			HeaderEncryptionMethod: headers.X25519ChaCha20IETFPoly1305,
			EncryptedHeaderPacket:  crypt4GHWriter.dataEncryptionParametersHeaderPacket,
		})
		if dataEditList != nil {
			headerPackets = append(headerPackets, headers.HeaderPacket{
				WriterPrivateKey:       writerPrivateKey,
				ReaderPublicKey:        readerPublicKey,
				HeaderEncryptionMethod: headers.X25519ChaCha20IETFPoly1305,
				EncryptedHeaderPacket:  dataEditList,
			})
		}
	}
	var magicNumber [8]byte
	copy(magicNumber[:], headers.MagicNumber)
	crypt4GHWriter.header = headers.Header{
		MagicNumber:       magicNumber,
		Version:           headers.Version,
		HeaderPacketCount: uint32(len(headerPackets)),
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

// ReCrypt4GHWriter re-encrypts a file by first re-encrypting the header and then attaching the new header to the file.
// The header is decrypted with a known key and re-encrypted for the new recievers.
// We keep reading the header and re-encrypting it separately so that ReEncryptHeader can be used independently
func ReCrypt4GHWriter(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte, readerPublicKeyList [][chacha20poly1305.KeySize]byte) (io.Reader, error) {

	oldHeader, err := headers.ReadHeader(reader)

	if err != nil {
		return nil, err
	}
	newHeader, err := headers.ReEncryptHeader(oldHeader, readerPrivateKey, readerPublicKeyList)
	if err != nil {
		return nil, err
	}

	// glue those bytes back onto the reader
	out := io.MultiReader(bytes.NewReader(newHeader), reader)

	return out, nil
}

// NewCrypt4GHWriter method constructs streaming.Crypt4GHWriter instance from io.Writer and reader's public key.
// Writer's public key is generated automatically.
func NewCrypt4GHWriterWithoutPrivateKey(writer io.Writer, readerPublicKeyList [][chacha20poly1305.KeySize]byte, dataEditList *headers.DataEditListHeaderPacket) (*Crypt4GHWriter, error) {
	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return NewCrypt4GHWriter(writer, privateKey, readerPublicKeyList, dataEditList)
}

// Write method implements io.Writer.Write.
func (c *Crypt4GHWriter) Write(p []byte) (n int, err error) {
	written := 0
	for ; written < len(p); written++ {
		if err := c.WriteByte(p[written]); err != nil {
			return written, err
		}
	}

	return written, nil
}

// WriteByte method implements io.ByteWriter.WriteByte.
func (c *Crypt4GHWriter) WriteByte(b byte) error {
	if c.buffer.Len() == c.buffer.Cap() {
		if err := c.flushBuffer(); err != nil {
			return err
		}
	}

	return c.buffer.WriteByte(b)
}

// Close method implements io.Closer.Close.
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
