package streaming

import (
	"../model/body"
	"../model/headers"
	"errors"
	"io"
)

type Crypt4GHInternalReader struct {
	reader io.Reader

	header                               headers.Header
	dataEncryptionParameterHeaderPackets []headers.DataEncryptionParametersHeaderPacket
	encryptedSegmentSize                 int

	buffer    []int
	bytesRead int
}

func NewCrypt4GHInternalReader(reader io.Reader, privateKey [32]byte) (*Crypt4GHInternalReader, error) {
	crypt4GHInternalReader := Crypt4GHInternalReader{}
	header, err := headers.NewHeader(reader, privateKey)
	crypt4GHInternalReader.reader = reader
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
	return &crypt4GHInternalReader, nil
}

func (c *Crypt4GHInternalReader) ReadByte() (byte, error) {
	if len(c.buffer) == 0 || len(c.buffer) == c.bytesRead {
		err := c.fillBuffer()
		if err != nil {
			return 0, err
		}
	}
	nextByte := c.buffer[c.bytesRead]
	if nextByte == -1 {
		return 0, io.EOF
	}
	c.bytesRead++
	return byte(nextByte), nil
}

func (c *Crypt4GHInternalReader) fillBuffer() error {
	c.bytesRead = 0
	encryptedSegmentBytes := make([]byte, c.encryptedSegmentSize)
	read, err := c.reader.Read(encryptedSegmentBytes)
	if err != nil {
		return err
	}
	if read == 0 {
		for i := range c.buffer {
			c.buffer[i] = -1
		}
	} else {
		segment, err := body.NewSegment(encryptedSegmentBytes[:read], c.dataEncryptionParameterHeaderPackets)
		if err != nil {
			return err
		}
		c.buffer = make([]int, len(segment.UnencryptedData))
		for i, b := range segment.UnencryptedData {
			c.buffer[i] = int(b)
		}
	}
	return nil
}
