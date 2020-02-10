package streaming

import (
	"../model/body"
	"../model/headers"
	"bytes"
	"errors"
	"io"
)

type Crypt4GHInternalReader struct {
	reader io.Reader

	header                               headers.Header
	dataEncryptionParameterHeaderPackets []headers.DataEncryptionParametersHeaderPacket
	encryptedSegmentSize                 int
	lastDecryptedSegment                 int
	buffer                               bytes.Buffer
}

func NewCrypt4GHInternalReader(reader io.Reader, privateKey [32]byte) (*Crypt4GHInternalReader, error) {
	crypt4GHInternalReader := Crypt4GHInternalReader{}
	header, err := headers.NewHeader(reader, privateKey)
	if err != nil {
		return nil, err
	}
	dataEncryptionParameterHeaderPackets, err := header.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		return nil, err
	}
	crypt4GHInternalReader.dataEncryptionParameterHeaderPackets = *dataEncryptionParameterHeaderPackets
	firstDataEncryptionParametersHeader := crypt4GHInternalReader.dataEncryptionParameterHeaderPackets[0]
	for _, dataEncryptionParametersHeader := range crypt4GHInternalReader.dataEncryptionParameterHeaderPackets {
		if dataEncryptionParametersHeader.GetPacketType() != firstDataEncryptionParametersHeader.GetPacketType() {
			return nil, errors.New("different data encryption methods are not supported")
		}
	}
	crypt4GHInternalReader.encryptedSegmentSize = firstDataEncryptionParametersHeader.EncryptedSegmentSize
	crypt4GHInternalReader.lastDecryptedSegment = -1
	crypt4GHInternalReader.reader = reader
	return &crypt4GHInternalReader, nil
}

func (c *Crypt4GHInternalReader) Read(p []byte) (n int, err error) {
	if c.buffer.Len() == 0 {
		err := c.fillBuffer()
		if err != nil {
			return 0, err
		}
	}
	return c.buffer.Read(p)
}

func (c *Crypt4GHInternalReader) ReadByte() (byte, error) {
	if c.buffer.Len() == 0 {
		err := c.fillBuffer()
		if err != nil {
			return 0, err
		}
	}
	return c.buffer.ReadByte()
}

func (c *Crypt4GHInternalReader) fillBuffer() error {
	encryptedSegmentBytes := make([]byte, c.encryptedSegmentSize)
	read, err := c.reader.Read(encryptedSegmentBytes)
	if err != nil {
		return err
	}
	if read == 0 {
		c.buffer.Truncate(0)
	} else {
		segment, err := body.NewSegment(encryptedSegmentBytes[:read], c.dataEncryptionParameterHeaderPackets)
		if err != nil {
			return err
		}
		c.buffer.Grow(len(segment.UnencryptedData))
		c.buffer.Write(segment.UnencryptedData)
	}
	return nil
}
