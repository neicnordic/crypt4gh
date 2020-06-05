package streaming

import (
	"bufio"
	"bytes"
	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/elixir-oslo/crypt4gh/model/headers"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestReencryption(t *testing.T) {
	tests := []struct {
		name    string
		discard int
	}{
		{
			name:    "no discard",
			discard: 0,
		},
		{
			name:    "within the first segment",
			discard: 100,
		},
		{
			name:    "on the edge",
			discard: headers.UnencryptedDataSegmentSize,
		},
		{
			name:    "within the second segment",
			discard: headers.UnencryptedDataSegmentSize + 100,
		},
		{
			name:    "out of range",
			discard: headers.UnencryptedDataSegmentSize * 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inFile, err := os.Open("../test/sample.txt")
			if err != nil {
				t.Error(err)
			}
			keyFile, err := os.Open("../test/ssh-ed25519-enc.sec.pem")
			if err != nil {
				t.Error(err)
			}
			writerPrivateKey, err := keys.ReadPrivateKey(keyFile, []byte("123123"))
			if err != nil {
				t.Error(err)
			}
			keyFile, err = os.Open("../test/crypt4gh-x25519-enc.pub.pem")
			if err != nil {
				t.Error(err)
			}
			readerPublicKey, err := keys.ReadPublicKey(keyFile)
			if err != nil {
				t.Error(err)
			}
			buffer := bytes.Buffer{}
			writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKey, nil)
			if err != nil {
				t.Error(err)
			}
			_, err = io.Copy(writer, inFile)
			if err != nil {
				t.Error(err)
			}
			err = inFile.Close()
			if err != nil {
				t.Error(err)
			}
			err = writer.Close()
			if err != nil {
				t.Error(err)
			}

			keyFile, err = os.Open("../test/crypt4gh-x25519-enc.sec.pem")
			if err != nil {
				t.Error(err)
			}
			readerSecretKey, err := keys.ReadPrivateKey(keyFile, []byte("password"))
			if err != nil {
				t.Error(err)
			}
			reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, nil)
			if err != nil {
				t.Error(err)
			}
			discarded, err := reader.Discard(test.discard)
			if err != nil {
				if test.discard != headers.UnencryptedDataSegmentSize*2 {
					t.Error(err)
				}
			}
			if discarded != test.discard {
				if test.discard != headers.UnencryptedDataSegmentSize*2 {
					t.Fail()
				}
			}
			all, err := ioutil.ReadAll(reader)
			if err != nil {
				t.Error(err)
			}
			inFile, err = os.Open("../test/sample.txt")
			if err != nil {
				t.Error(err)
			}
			inBytes, err := ioutil.ReadAll(inFile)
			if err != nil {
				t.Error(err)
			}
			toDiscard := test.discard
			if test.discard > len(inBytes) {
				toDiscard = len(inBytes)
			}
			if !bytes.Equal(all, inBytes[toDiscard:]) {
				t.Fail()
			}
		})
	}
}

func TestReencryptionWithDataEditListInCrypt4GHWriterNoDiscard(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	keyFile, err := os.Open("../test/ssh-ed25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(keyFile, []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	buffer := bytes.Buffer{}
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKey, &dataEditListHeaderPacket)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(keyFile, []byte("password"))
	if err != nil {
		t.Error(err)
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, nil)
	if err != nil {
		t.Error(err)
	}
	all, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	inBytes, err := ioutil.ReadAll(inFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(all[:837], inBytes[950:950+837]) {
		t.Fail()
	}
}

func TestReencryptionWithDataEditListInCrypt4GHReaderNoDiscard(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	keyFile, err := os.Open("../test/ssh-ed25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(keyFile, []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKey, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(keyFile, []byte("password"))
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, &dataEditListHeaderPacket)
	if err != nil {
		t.Error(err)
	}
	all, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	inBytes, err := ioutil.ReadAll(inFile)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(all[:837], inBytes[950:950+837]) {
		t.Fail()
	}
}

func TestReencryptionWithDataEditListAndDiscard(t *testing.T) {
	toDiscard := 100
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	keyFile, err := os.Open("../test/ssh-ed25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(keyFile, []byte("123123"))
	if err != nil {
		t.Error(err)
	}
	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		t.Error(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(keyFile)
	if err != nil {
		t.Error(err)
	}
	buffer := bytes.Buffer{}
	writer, err := NewCrypt4GHWriter(&buffer, writerPrivateKey, readerPublicKey, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		t.Error(err)
	}
	err = inFile.Close()
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.sec.pem")
	if err != nil {
		t.Error(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(keyFile, []byte("password"))
	if err != nil {
		t.Error(err)
	}
	dataEditListHeaderPacket := headers.DataEditListHeaderPacket{
		PacketType:    headers.PacketType{PacketType: headers.DataEditList},
		NumberLengths: 4,
		Lengths:       []uint64{950, 837, 510, 847},
	}
	reader, err := NewCrypt4GHReader(&buffer, readerSecretKey, &dataEditListHeaderPacket)
	if err != nil {
		t.Error(err)
	}
	discarded, err := reader.Discard(toDiscard)
	if err != nil {
		t.Error(err)
	}
	if discarded != toDiscard {
		t.Fail()
	}
	all, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	inFile, err = os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	bufioReader := bufio.NewReader(inFile)
	_, err = bufioReader.Discard(950 + toDiscard)
	if err != nil {
		t.Error(err)
	}
	firstLine, _, err := bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	_, _, err = bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	_, _, err = bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	_, _, err = bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	secondLine, _, err := bufioReader.ReadLine()
	if err != nil {
		t.Error(err)
	}
	expectedText := strings.TrimSpace(string(firstLine) + "\n" + string(secondLine))
	actualText := strings.TrimSpace(string(all))
	if !strings.EqualFold(expectedText, actualText) {
		t.Fail()
	}
}
