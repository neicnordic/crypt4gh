// Package streaming contains Writer and Reader implementing
// Crypt4GH encryption and decryption correspondingly.
package streaming

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/neicnordic/crypt4gh/model/body"
	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
)

// crypt4GHInternalReader is the internal structure for managing
// the stream reader
type crypt4GHInternalReader struct {
	// reader is the Reader providing the encrypted stream data
	// is consumed from.
	reader io.Reader

	// header is a binary copy of the C4GH file header.
	header []byte

	// dataEncryptionParametersHeaderPackets may be one or more
	// DataEncryptionParametersHeaderPacket:s. These provide e.g. symmetric
	// keys for decrypting segments.
	dataEncryptionParametersHeaderPackets []headers.DataEncryptionParametersHeaderPacket

	// dataEditList possibly contains a pointer to a list of edits to apply
	// (skip) when consuming the stream.
	dataEditList *headers.DataEditListHeaderPacket

	// encryptedSegmentSize is the size of a segment in the encrypted stream,
	// i.e. 65536 (data)+any extras added such as MAC or nonce.
	encryptedSegmentSize int

	// lastDecryptedSegment is the number of the segment that was last decrypted
	// (is available in buffer, if any).
	lastDecryptedSegment int64

	// buffer is where decrypted data is stored temporarily for consumption. It
	// contains at most one segments worth of data.
	buffer bytes.Buffer

	// bufferUse is the size of the last segment put into buffer at the time of
	// writing. bufferUse-buffer.Len() give the number of bytes consumed from
	// the buffer already. (Go 1.21 introduces buffer.Available() which allows
	// for getting rid of this together with Len() and Cap()).
	bufferUse int

	// streamPos is the current offset in the logical consumer stream, i.e.
	// where Read or ReadByte should return data from.
	streamPos int64

	// sourcePos is the current offset in reader providing the encrypted stream.
	sourcePos int64

	// sourceStart is the offset for the start of the first encrypted segment.
	sourceStart int64
}

// newCrypt4GHInternalReader returns a crypt4GHInternalReader initialised from
// the passed parameters. Returns a pointer or nil and any error encountered.
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
	// data encryption methods are the same (standard requirement and validated above), so
	// we can just pick the size from the first.
	crypt4GHInternalReader.encryptedSegmentSize = firstDataEncryptionParametersHeader.EncryptedSegmentSize
	crypt4GHInternalReader.lastDecryptedSegment = -1
	crypt4GHInternalReader.reader = reader

	crypt4GHInternalReader.streamPos = 0
	crypt4GHInternalReader.sourcePos = 0

	if s, seekable := reader.(io.ReadSeeker); seekable {
		// Figure out the offset in the file data starts at (end of headers)
		// (move 0 bytes from current position - whence 1)
		crypt4GHInternalReader.sourceStart, err = s.Seek(0, 1)

		if err != nil {
			return nil, err
		}
	}

	return &crypt4GHInternalReader, nil
}

// ensureBuffer ensure the decrypted buffer is not empty
// unless we have reached the end of the stream
// it also makes sure any remaining data in the buffer
// matches what should be observed in the consumer stream
// at c.streamPos, specifically a Read or ReadByte will
// return the data that should be seen at c.streamPos and
// forward
//
// Returns any error encountered.
func (c *crypt4GHInternalReader) ensureBuffer() (err error) {

	neededSegment, err := c.consumerOffsetToSegment(c.streamPos)
	if err != nil {
		// Outside of file? Forward error (EOF)
		return err
	}

	neededPos, err := c.consumerOffsetToEncryptedStreamOffset(c.streamPos)
	if err != nil {
		return err
	}

	// Figure out the needed offset within the segment
	segmentOffset := int(neededPos - neededSegment*int64(headers.UnencryptedDataSegmentSize))
	bufferOffset := c.bufferUse - c.buffer.Len()

	if c.lastDecryptedSegment != neededSegment || segmentOffset < bufferOffset {
		// If we want to read another segment than the current or if we've
		// already read past the desired offset, we need to fetch data, signal
		// this by throwing away whatever we currently have
		c.buffer.Reset()
	}

	// If we don't have any data on hand, fetch more
	if c.buffer.Len() == 0 {
		if err := c.fillBuffer(); err != nil {
			return err
		}
		bufferOffset = 0
	}

	// Find the correct place in the buffert
	if bufferOffset < segmentOffset {
		toSkip := int(segmentOffset) - bufferOffset
		_ = c.buffer.Next(toSkip)
	}

	return nil
}

// consumerOffsetToSegment returns the segment in the underlying stream
// for the passed consumer offset.
//
// It can possibly return error EOF if the passed offset is outside
// of the exposed stream, but this is not guaranteed
func (c *crypt4GHInternalReader) consumerOffsetToSegment(n int64) (int64, error) {
	// Figure out the segment

	eo, err := c.consumerOffsetToEncryptedStreamOffset(n)
	segment := eo / int64(headers.UnencryptedDataSegmentSize)

	return segment, err
}

// consumerOffsetToSEncryptedStreamOffset returns the offset in the underlying
// stream for the passed consumer offset. This is excluding the extra bytes
// added by the crypt4gh file format (e.g. headers or segment nonce and mac).
//
// It can possibly return error EOF if the passed offset is outside of the
// exposed stream, but this is not guaranteed.
func (c *crypt4GHInternalReader) consumerOffsetToEncryptedStreamOffset(n int64) (int64, error) {
	// Calculate the offset in the encrypted stream from the consumer visible
	// offset
	//
	// The returned offset does *not* include the header size or the additional
	// bytes added for each segment (e.g. nonce, MAC)

	if c.dataEditList == nil || c.dataEditList.NumberLengths == 0 {
		// No data edit list - offset is unchanged
		return n, nil
	}

	toCheck := int(c.dataEditList.NumberLengths)
	keepSkipList := c.dataEditList.Lengths
	skip := true

	var i int
	var underlyingPos, exposedPos int64 = 0, 0

	// Walk through list but stop if we've past the offset
	for ; i < toCheck && exposedPos <= n; i++ {
		if !skip {
			// Stream presented to consumer only advances if not skipped
			nextExposedPos := exposedPos + int64(keepSkipList[i])

			if exposedPos <= n && nextExposedPos > n {
				// Not skipping and within this window,
				// calculate and return the offset

				return underlyingPos + n - exposedPos, nil
			}

			exposedPos = nextExposedPos
		}

		// Underlying stream moves forward no matter if it's skipped or not.
		underlyingPos += int64(keepSkipList[i])

		skip = !skip
	}

	if i == toCheck && skip {
		// Last entry seen was for keeping, skip rest of stream
		return underlyingPos, io.EOF
	}

	// If last entry seen was skipping, include rest of stream
	return n + underlyingPos - exposedPos, nil
}

// readByte implements the work of the ReadByte function,
// reading just one byte at maximum.
//
// Returns the byte read or any error encountered
func (c *crypt4GHInternalReader) readByte() (byte, error) {
	if err := c.ensureBuffer(); err != nil {
		return 0, err
	}

	b, err := c.buffer.ReadByte()

	if err == nil {
		c.streamPos++
	}

	return b, err
}

// read implements the underpinnings of the Read function, serving
// up the unencrypted stream.
//
// Accepts the slice to read into, returns the number of bytes
// read and any error encountered
func (c *crypt4GHInternalReader) read(p []byte) (n int, err error) {
	haveRead := 0

	for haveRead < len(p) {
		// We have space to read more?

		// Make sure we have a valid buffer for our position
		if err := c.ensureBuffer(); err != nil {
			return haveRead, err
		}

		canRead := len(p[haveRead:])
		remainingInBuffer := c.bufferUse - c.buffer.Len()

		if remainingInBuffer < canRead {
			canRead = remainingInBuffer
		}

		start, err := c.consumerOffsetToEncryptedStreamOffset(c.streamPos)
		if err != nil {
			return haveRead, err
		}

		end, _ := c.consumerOffsetToEncryptedStreamOffset(c.streamPos + int64(canRead))
		// Ignore if the end is outside of the file, will trigger EOF "normally"
		// anyway

		if (end - start) != int64(canRead) {
			// There's a gap somewhere close, read byte by byte.

			startedAt := haveRead

			// Do not try to read the entire desired amount byte for byte
			// but rather try at most the rest of our buffer
			// after that fall out to the outer loop again
			for (startedAt-haveRead) < canRead && haveRead < len(p) {

				p[haveRead], err = c.readByte()
				if err != nil {
					// Error? Fall out
					return haveRead, err
				}
				haveRead++
			}
		} else {
			// We can just read the rest of the buffer

			r, err := c.buffer.Read(p[haveRead:])
			haveRead += r
			c.streamPos += int64(r)

			// Not sure why we'd get an error here, but forward
			// if we see that
			if err != nil {
				return haveRead, err
			}
		}
	}

	return haveRead, nil
}

// fillBuffer makes sure there is data available for reading unless
// we are at EOF.
// Returns any error encountered (e.g. EOF or read error that can
// possibly be due to data corruption).
func (c *crypt4GHInternalReader) fillBuffer() error {
	encryptedSegmentBytes := make([]byte, c.encryptedSegmentSize)
	neededSegment, err := c.consumerOffsetToSegment(c.streamPos)

	if err != nil {
		return err
	}

	segmentPos := neededSegment * int64(c.encryptedSegmentSize)

	// nolint:nestif
	if segmentPos != c.sourcePos {
		if r, seekable := c.reader.(io.ReadSeeker); seekable {
			// If we can seek, do so, this may allow skipping fetching
			// large amounts of data
			o := segmentPos + c.sourceStart
			offset, err := r.Seek(o, 0)

			if err != nil {
				return err
			}
			c.sourcePos = offset
		} else {
			// Not seekable, figure out how much we need to skip
			skip := segmentPos - c.sourcePos

			for skip > int64(0) {
				canRead := int64(len(encryptedSegmentBytes))
				if canRead > skip {
					canRead = skip
				}
				read, err := c.reader.Read(encryptedSegmentBytes[:canRead])

				if err != nil {
					// Since we're trying to skip forward to our desired block
					// any error goes out
					return err
				}
				skip -= int64(read)
			}
		}
	}

	// reader should be positioned before the needed segment now

	read, err := io.ReadFull(c.reader, encryptedSegmentBytes)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}

	c.bufferUse = 0
	c.buffer.Reset()

	if read == 0 {
		// Should we fail here? We'll reasonably eventually get
		// an EOF anyway
		return nil
	}

	segment := body.Segment{DataEncryptionParametersHeaderPackets: c.dataEncryptionParametersHeaderPackets}
	if err = segment.UnmarshalBinary(encryptedSegmentBytes[:read]); err != nil {
		return err
	}
	c.lastDecryptedSegment = neededSegment
	c.sourcePos += int64(read)

	// Keep track of how much data is directly available

	if c.bufferUse, err = c.buffer.Write(segment.UnencryptedData); err != nil {
		return err
	}

	return nil
}

// seek implements the actual support for Seek, moves the stream
// (if possible) to the position derived from whence and offset
// returns the new position and/or any error encountered.
func (c *crypt4GHInternalReader) seek(offset int64, whence int) (pos int64, err error) {
	if whence == 2 {
		return -1, errors.New("Seeking from end not supported")
	}

	if whence < 0 || whence > 2 {
		return -1, errors.New("Bad whence")
	}

	_, seekable := c.reader.(io.Seeker)

	if !seekable && ((whence == 0 && offset < c.streamPos) || (whence == 1 && offset < 0)) {
		return -1, errors.New("Seeking backwards only supported when offered by underlying resource")
	}

	if whence == 1 {
		c.streamPos += offset
	} else {
		c.streamPos = offset
	}

	return c.streamPos, nil
}

// close method closes the reader, invalidating it. Any error
// encountered is returned.
func (c *crypt4GHInternalReader) close() (err error) {
	r, closable := c.reader.(io.Closer)

	c.reader = nil

	if !closable {
		// Assume we don't need to do anything, should we fail instead?
		return nil
	}

	err = r.Close()

	return err
}

// Crypt4GHReader structure keeps the structure for the internal
// implementation, providing methods for io.Reader,
// io.ByteReader, io.Seeker, io.Closer.
type Crypt4GHReader struct {
	// reader is the internal crypt4GHInternalReader used for managing state
	// and providing relevant methods.
	reader crypt4GHInternalReader
	// mut is a Mutex that provides thread safety.
	mut sync.Mutex
}

// NewCrypt4GHReader method constructs streaming.Crypt4GHReader instance from
// io.Reader and corresponding key. Allows for overriding data edit list
// from stream, returns the struct pointer or nil and any error encountered.
func NewCrypt4GHReader(reader io.Reader, readerPrivateKey [chacha20poly1305.KeySize]byte, dataEditList *headers.DataEditListHeaderPacket) (*Crypt4GHReader, error) {
	internalReader, err := newCrypt4GHInternalReader(reader, readerPrivateKey)
	if err != nil {
		return nil, err
	}
	crypt4GHReader := Crypt4GHReader{
		reader: *internalReader,
	}
	if dataEditList != nil {
		crypt4GHReader.reader.dataEditList = dataEditList
	}

	return &crypt4GHReader, nil
}

// GetHeader method returns the bytes for the Crypt4GH header for the current
// stream.
func (c *Crypt4GHReader) GetHeader() []byte {
	// No locking here, reader.header is not used

	return c.reader.header
}

// Discard advances the stream without returning the data, returns
// the skipped amount and possible error encountered.
func (c *Crypt4GHReader) Discard(skip int) (n int, err error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	discarded := 0

	for discarded < skip {

		_, err = c.reader.readByte()

		if err != nil {
			return discarded, err
		}
		discarded++
	}

	return discarded, nil
}

// Read method implements io.Reader.Read for the Crypt4GHReader.
func (c *Crypt4GHReader) Read(p []byte) (n int, err error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	return c.reader.read(p)
}

// ReadByte method implements io.ByteReader.ReadByte for the Crypt4GHReader.
func (c *Crypt4GHReader) ReadByte() (byte, error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	return c.reader.readByte()
}

// Seek method implements io.Seeker.Seek for the Crypt4GHReader.
func (c *Crypt4GHReader) Seek(offset int64, whence int) (pos int64, err error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	return c.reader.seek(offset, whence)
}

// Close method implements io.Closer.Close for the Crypt4GHReader.
func (c *Crypt4GHReader) Close() (err error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	return c.reader.close()
}
