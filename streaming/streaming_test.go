package streaming

import (
	"../keys"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestReencryption(t *testing.T) {
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
	_, err = reader.Discard(4)
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
	if bytes.Compare(all, inBytes[4:]) != 0 {
		t.Fail()
	}
}
