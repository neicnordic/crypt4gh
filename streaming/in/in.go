package in

import (
	"../../model/body"
	"../../model/headers"
	"bytes"
	"container/list"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type crypt4GHInternalReader struct {
	reader io.Reader

	header                                headers.Header
	dataEncryptionParametersHeaderPackets []headers.DataEncryptionParametersHeaderPacket
	encryptedSegmentSize                  int
	lastDecryptedSegment                  int
	buffer                                bytes.Buffer
}

func newCrypt4GHInternalReader(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte) (*crypt4GHInternalReader, error) {
	crypt4GHInternalReader := crypt4GHInternalReader{}
	header, err := headers.NewHeader(reader, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	dataEncryptionParameterHeaderPackets, err := header.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		return nil, err
	}
	crypt4GHInternalReader.dataEncryptionParametersHeaderPackets = *dataEncryptionParameterHeaderPackets
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
		return 0, nil
	}
	if c.buffer.Len() == 0 {
		err := c.fillBuffer()
		if err != nil {
			return 0, err
		}
	}
	bytesRead := c.buffer.Cap() - c.buffer.Len()
	currentDecryptedPosition := c.lastDecryptedSegment*headers.UnencryptedDataSegmentSize + bytesRead
	newDecryptedPosition := currentDecryptedPosition + n
	newSegmentNumber := newDecryptedPosition / headers.UnencryptedDataSegmentSize
	if newSegmentNumber != c.lastDecryptedSegment {
		segmentsToDiscard := newSegmentNumber - c.lastDecryptedSegment - 1
		err := c.discardSegments(segmentsToDiscard)
		if err != nil {
			return 0, err
		}
		err = c.fillBuffer()
		bytesRead = c.buffer.Cap() - c.buffer.Len()
		if err != nil {
			return 0, err
		}
		currentDecryptedPosition = c.lastDecryptedSegment * headers.UnencryptedDataSegmentSize
	}
	delta := newDecryptedPosition - currentDecryptedPosition
	if bytesRead+delta > c.buffer.Len() {
		missingBytes := bytesRead + delta - c.buffer.Len()
		c.buffer.Next(delta - missingBytes)
		return n - missingBytes, nil
	}
	c.buffer.Next(delta)
	return n, nil
}

func (c *crypt4GHInternalReader) discardSegments(n int) error {
	bytesToSkip := make([]byte, n)
	_, err := c.reader.Read(bytesToSkip)
	if err != nil {
		return err
	}
	c.lastDecryptedSegment++
	return nil
}

func (c *crypt4GHInternalReader) fillBuffer() error {
	encryptedSegmentBytes := make([]byte, c.encryptedSegmentSize)
	read, err := c.reader.Read(encryptedSegmentBytes)
	if err != nil {
		return err
	}
	if read == 0 {
		c.buffer.Truncate(0)
	} else {
		segment := body.Segment{DataEncryptionParametersHeaderPackets: c.dataEncryptionParametersHeaderPackets}
		err := segment.UnmarshalBinary(encryptedSegmentBytes[:read])
		if err != nil {
			return err
		}
		c.buffer.Grow(len(segment.UnencryptedData))
		c.buffer.Write(segment.UnencryptedData)
		c.lastDecryptedSegment++
	}
	return nil
}

type Crypt4GHReader struct {
	reader crypt4GHInternalReader

	useDataEditList bool
	lengths         list.List
	bytesRead       uint64
}

func NewCrypt4GHReader(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte, dataEditList *headers.DataEditListHeaderPacket) (*Crypt4GHReader, error) {
	internalReader, err := newCrypt4GHInternalReader(reader, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	crypt4GHReader := Crypt4GHReader{
		reader:          *internalReader,
		useDataEditList: dataEditList != nil,
		lengths:         list.List{},
		bytesRead:       0,
	}
	if dataEditList != nil {
		skip := true
		for i := uint32(0); i < dataEditList.NumberLengths; i++ {
			crypt4GHReader.lengths.PushFront(DataEditListEntry{
				length: dataEditList.Lengths[i],
				skip:   skip,
			})
			skip = !skip
		}
	}
	return &crypt4GHReader, nil
}

func (c *Crypt4GHReader) Read(p []byte) (n int, err error) {
	readByte, err := c.ReadByte()
	if err != nil {
		return 0, err
	}
	p[0] = readByte
	i := 1
	for ; i < len(p); i++ {
		readByte, err := c.ReadByte()
		if err != nil {
			return i, err
		}
		p[i] = readByte
	}
	return i, nil
}

func (c *Crypt4GHReader) ReadByte() (byte, error) {
	if c.useDataEditList {
		return c.readByteWithDataEditList()
	} else {
		return c.reader.ReadByte()
	}
}

func (c *Crypt4GHReader) readByteWithDataEditList() (byte, error) {
	if c.lengths.Len() != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(DataEditListEntry)
		if dataEditListEntry.skip {
			_, err := c.reader.Discard(int(dataEditListEntry.length))
			if err != nil {
				return 0, err
			}
			c.lengths.Remove(element)
		}
	}
	if c.lengths.Len() != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(DataEditListEntry)
		length := dataEditListEntry.length
		if c.bytesRead == length {
			c.lengths.Remove(element)
			c.bytesRead = 0
			return c.readByteWithDataEditList()
		}
	}
	return 0, io.EOF
}

func (c *Crypt4GHReader) Discard(n int) (discarded int, err error) {
	if c.useDataEditList {
		return c.discardWithDataEditList(n)
	} else {
		return c.reader.Discard(n)
	}
}

func (c *Crypt4GHReader) discardWithDataEditList(n int) (int, error) {
	bytesDiscarded := 0
	if c.lengths.Len() != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(DataEditListEntry)
		if dataEditListEntry.skip {
			discarded, err := c.reader.Discard(int(dataEditListEntry.length))
			if err != nil {
				return bytesDiscarded + discarded, err
			}
			c.lengths.Remove(element)
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
				} else {
					discarded, err := c.reader.Discard(int(bytesLeftToRead))
					if err != nil {
						return bytesDiscarded + discarded, err
					}
					bytesDiscarded += discarded
					n -= int(bytesLeftToRead)
					c.lengths.Remove(element)
					c.bytesRead = 0
				}
			}
		}
	}
	for c.lengths.Len() != 0 && n != 0 {
		element := c.lengths.Front()
		dataEditListEntry := element.Value.(DataEditListEntry)
		if dataEditListEntry.skip {
			discarded, err := c.reader.Discard(int(dataEditListEntry.length))
			if err != nil {
				return bytesDiscarded + discarded, err
			}
			c.lengths.Remove(element)
		} else {
			length := dataEditListEntry.length
			if uint64(n) <= length {
				discarded, err := c.reader.Discard(n)
				if err != nil {
					return bytesDiscarded + discarded, err
				}
				bytesSkippedJustNow := discarded
				c.bytesRead += uint64(bytesSkippedJustNow)
				bytesDiscarded += bytesSkippedJustNow
				return bytesDiscarded, nil
			} else {
				discarded, err := c.reader.Discard(int(length))
				if err != nil {
					return bytesDiscarded + discarded, err
				}
				bytesDiscarded += discarded
				n -= int(length)
				c.lengths.Remove(element)
			}
		}
	}
	return bytesDiscarded, nil
}

type DataEditListEntry struct {
	length uint64
	skip   bool
}
