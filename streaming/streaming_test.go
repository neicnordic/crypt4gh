package streaming

import (
	"bytes"
	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/elixir-oslo/crypt4gh/model/headers"
	"io"
	"io/ioutil"
	"os"
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
			name:    "discard 100",
			discard: 100,
		},
		{
			name:    "discard UnencryptedDataSegmentSize",
			discard: headers.UnencryptedDataSegmentSize,
		},
		{
			name:    "discard UnencryptedDataSegmentSize + 100",
			discard: headers.UnencryptedDataSegmentSize + 100,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inFile, err := os.Open("../test/sample.txt")
			if err != nil {
				t.Error(err)
			}
			buf := bytes.Buffer{}
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
			writer, err := NewCrypt4GHWriter(&buf, writerPrivateKey, readerPublicKey, nil)
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
			reader, err := NewCrypt4GHReader(&buf, readerSecretKey, nil)
			if err != nil {
				t.Error(err)
			}
			discarded, err := reader.Discard(test.discard)
			if err != nil {
				t.Error(err)
			}
			if discarded != test.discard {
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
			inBytes, err := ioutil.ReadAll(inFile)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(all, inBytes[test.discard:]) {
				t.Fail()
			}
		})
	}
}

func TestReencryptionWithDataEditList(t *testing.T) {
	inFile, err := os.Open("../test/sample.txt")
	if err != nil {
		t.Error(err)
	}
	buf := bytes.Buffer{}
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
	writer, err := NewCrypt4GHWriter(&buf, writerPrivateKey, readerPublicKey, &dataEditListHeaderPacket)
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
	reader, err := NewCrypt4GHReader(&buf, readerSecretKey, nil)
	if err != nil {
		t.Error(err)
	}
	//discarded, err := reader.Discard(test.discard)
	//if err != nil {
	//	t.Error(err)
	//}
	//if discarded != test.discard {
	//	t.Fail()
	//}
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
