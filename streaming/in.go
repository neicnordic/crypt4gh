// Package streaming contains writer and reader implementing Crypt4GH encryption and decryption correspondingly.
package streaming

import (
	"bytes"
	"container/list"
	"errors"
	"io"

	"github.com/elixir-oslo/crypt4gh/model/body"
	"github.com/elixir-oslo/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
)

type crypt4GHInternalReader struct {
	reader io.Reader

	header                                []byte
	dataEncryptionParametersHeaderPackets []headers.DataEncryptionParametersHeaderPacket
	dataEditList                          *headers.DataEditListHeaderPacket
	encryptedSegmentSize                  int
	lastDecryptedSegment                  int
	buffer                                bytes.Buffer
}

func newCrypt4GHInternalReader(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte) (*crypt4GHInternalReader, error) {
	binaryHeader, err := headers.ReadHeader(reader)
	if err != nil {
		return nil, err
	}
	crypt4GHInternalReader := crypt4GHInternalReader{header: make([]byte, len(binaryHeader))}
	copy(crypt4GHInternalReader.header, binaryHeader)
	buffer := bytes.NewBuffer(binaryHeader)
	header, err := headers.NewHeader(buffer, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	dataEncryptionParameterHeaderPackets, err := header.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		return nil, err
	}
	crypt4GHInternalReader.dataEncryptionParametersHeaderPackets = *dataEncryptionParameterHeaderPackets
	crypt4GHInternalReader.dataEditList = header.GetDataEditListHeaderPacket()
	firstDataEncryptionParametersHeader := crypt4GHInternalReader.dataEncryptionParametersHeaderPackets[0]
	for _, dataEncryptionParametersHeader := range crypt4GHInternalReader.dataEncryptionParametersHeaderPackets {
		if dataEncryptionParametersHeader.GetPacketType() != firstDataEncryptionParametersHeader.GetPacketType() {
			return nil, errors.New("different data encryption methods are not supported")
		}
	}
	crypt4GHInternalReader.encryptedSegmentSize = firstDataEncryptionParametersHeader.EncryptedSegmentSize
	crypt4GHInternalReader.lastDecryptedSegment = -1
	crypt4GHInternalReader.reader = reader
	return &crypt4GHInternalReader, nil
}

func (c *crypt4GHInternalReader) Read(p []byte) (n int, err error) {
	if c.buffer.Len() == 0 {
		err := c.fillBuffer()
		if err != nil {
			return 0, err
		}
	}
	return c.buffer.Read(p)
}

func (c *crypt4GHInternalReader) ReadByte() (byte, error) {
	if c.buffer.Len() == 0 {
		err := c.fillBuffer()
		if err != nil {
			return 0, err
		}
	}
	return c.buffer.ReadByte()
}

func (c *crypt4GHInternalReader) Discard(n int) (discarded int, err error) {
	if n < 0 {
		return
	}
	if c.buffer.Len() == 0 {
		err = c.fillBuffer()
		if err != nil {
			return
		}
	}
	bytesRead := c.buffer.Cap() - c.buffer.Len()
	currentDecryptedPosition := c.lastDecryptedSegment*headers.UnencryptedDataSegmentSize + bytesRead
	newDecryptedPosition := currentDecryptedPosition + n
	newSegmentNumber := newDecryptedPosition / headers.UnencryptedDataSegmentSize
	if newSegmentNumber != c.lastDecryptedSegment {
		segmentsToDiscard := newSegmentNumber - c.lastDecryptedSegment - 1
		discarded, err = c.discardSegments(segmentsToDiscard)
		if err != nil {
			return discarded, err
		}
		err = c.fillBuffer()
		if err != nil {
			c.buffer.Reset()
			return discarded, err
		}
		discarded += headers.UnencryptedDataSegmentSize
		currentDecryptedPosition = c.lastDecryptedSegment * headers.UnencryptedDataSegmentSize
	}
	delta := newDecryptedPosition - currentDecryptedPosition
	c.buffer.Next(delta)
	return discarded + delta, err
}

func (c *crypt4GHInternalReader) discardSegments(segments int) (bytesDiscarded int, err error) {
	if segments <= 0 {
		return
	}
	for i := 0; i < segments; i++ {
		discarded := 0
		discarded, err = c.discardSegment()
		bytesDiscarded += discarded
		if err != nil {
			return
		}
	}
	return
}

func (c *crypt4GHInternalReader) discardSegment() (bytesDiscarded int, err error) {
	bytesToSkip := make([]byte, c.encryptedSegmentSize)
	bytesDiscarded, err = c.reader.Read(bytesToSkip)
	if err != nil {
		return
	}
	c.lastDecryptedSegment++
	return
}

func (c *crypt4GHInternalReader) fillBuffer() error {
	encryptedSegmentBytes := make([]byte, c.encryptedSegmentSize)

	read := 1
	var err error
	totalread := 0

	for read != 0 && totalread != c.encryptedSegmentSize {
		read, err = c.reader.Read(encryptedSegmentBytes)
		if err != nil {
			return err
		}

		totalread += read
	}

	if read == 0 {
		c.buffer.Reset()
		return nil
	}

	c.buffer.Reset()
	segment := body.Segment{DataEncryptionParametersHeaderPackets: c.dataEncryptionParametersHeaderPackets}
	err = segment.UnmarshalBinary(encryptedSegmentBytes[:read])
	if err != nil {
		return err
	}
	_, err = c.buffer.Write(segment.UnencryptedData)
	if err != nil {
		return err
	}
	c.lastDecryptedSegment++

	return nil
}

// Crypt4GHReader structure implements io.Reader and io.ByteReader.
type Crypt4GHReader struct {
	reader crypt4GHInternalReader

	useDataEditList bool
	lengths         list.List
	bytesRead       uint64
}

// NewCrypt4GHReader method constructs streaming.Crypt4GHReader instance from io.Reader and corresponding key.
func NewCrypt4GHReader(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte, dataEditList *headers.DataEditListHeaderPacket) (*Crypt4GHReader, error) {
	internalReader, err := newCrypt4GHInternalReader(reader, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	crypt4GHReader := Crypt4GHReader{
		reader:          *internalReader,
		useDataEditList: dataEditList != nil || internalReader.dataEditList != nil,
		lengths:         list.List{},
		bytesRead:       0,
	}
	if dataEditList != nil {
		skip := true
		for i := uint32(0); i < dataEditList.NumberLengths; i++ {
			crypt4GHReader.lengths.PushBack(dataEditListEntry{
				length: dataEditList.Lengths[i],
				skip:   skip,
			})
			skip = !skip
		}
	} else if internalReader.dataEditList != nil {
		skip := true
		for i := uint32(0); i < internalReader.dataEditList.NumberLengths; i++ {
			crypt4GHReader.lengths.PushBack(dataEditListEntry{
				length: internalReader.dataEditList.Lengths[i],
				skip:   skip,
			})
			skip = !skip
		}
	}
	return &crypt4GHReader, nil
}

// Read method implements io.Reader.Read.
func (c *Crypt4GHReader) Read(p []byte) (n int, err error) {
	readByte, err := c.ReadByte()
	if err != nil {
		return
	}
	p[0] = readByte
	n = 1
	for ; n < len(p); n++ {
		readByte, err = c.ReadByte()
		if err != nil {
			return
		}
		p[n] = readByte
	}
	return
}

// ReadByte method implements io.ByteReader.ReadByte.
func (c *Crypt4GHReader) ReadByte() (byte, error) {
	if c.useDataEditList {
		return c.readByteWithDataEditList()
	}
	return c.reader.ReadByte()
}

func (c *Crypt4GHReader) readByteWithDataEditList() (byte, error) {
	if c.lengths.Len() != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(dataEditListEntry)
		if dataEditListEntry.skip {
			_, err := c.reader.Discard(int(dataEditListEntry.length))
			c.lengths.Remove(element)
			if err != nil {
				return 0, err
			}
		}
	}
	if c.lengths.Len() != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(dataEditListEntry)
		length := dataEditListEntry.length
		if c.bytesRead == length {
			c.lengths.Remove(element)
			c.bytesRead = 0
			return c.readByteWithDataEditList()
		}
		c.bytesRead++
		return c.reader.ReadByte()
	}
	return 0, io.EOF
}

// Discard method skips the next n bytes, returning the number of bytes discarded.
func (c *Crypt4GHReader) Discard(n int) (discarded int, err error) {
	if n <= 0 {
		return
	}
	if c.useDataEditList {
		return c.discardWithDataEditList(n)
	}
	return c.reader.Discard(n)
}

func (c *Crypt4GHReader) discardWithDataEditList(n int) (int, error) {
	bytesDiscarded := 0
	if c.lengths.Len() != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(dataEditListEntry)
		if dataEditListEntry.skip {
			discarded, err := c.reader.Discard(int(dataEditListEntry.length))
			c.lengths.Remove(element)
			if err != nil {
				return bytesDiscarded + discarded, err
			}
		} else {
			length := dataEditListEntry.length
			if c.bytesRead == length {
				c.lengths.Remove(element)
				c.bytesRead = 0
			} else {
				bytesLeftToRead := length - c.bytesRead
				if uint64(n) <= bytesLeftToRead {
					c.bytesRead += uint64(n)
					return c.reader.Discard(n)
				}
				discarded, err := c.reader.Discard(int(bytesLeftToRead))
				bytesDiscarded += discarded
				n -= int(bytesLeftToRead)
				c.lengths.Remove(element)
				c.bytesRead = 0
				if err != nil {
					return bytesDiscarded, err
				}
			}
		}
	}
	for c.lengths.Len() != 0 && n != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(dataEditListEntry)
		if dataEditListEntry.skip {
			discarded, err := c.reader.Discard(int(dataEditListEntry.length))
			c.lengths.Remove(element)
			if err != nil {
				return bytesDiscarded + discarded, err
			}
		} else {
			length := dataEditListEntry.length
			if uint64(n) <= length {
				discarded, err := c.reader.Discard(n)
				if err != nil {
					return bytesDiscarded + discarded, err
				}
				c.bytesRead += uint64(discarded)
				bytesDiscarded += discarded
				return bytesDiscarded, nil
			}
			discarded, err := c.reader.Discard(int(length))
			bytesDiscarded += discarded
			n -= int(length)
			c.lengths.Remove(element)
			if err != nil {
				return bytesDiscarded, err
			}
		}
	}
	return bytesDiscarded, nil
}

// GetHeader method returns Crypt4GH header structure.
func (c Crypt4GHReader) GetHeader() []byte {
	return c.reader.header
}

type dataEditListEntry struct {
	length uint64
	skip   bool
}
