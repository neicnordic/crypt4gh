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
		panic(err)
	}
	buf := bytes.Buffer{}
	keyFile, err := os.Open("../test/ssh-ed25519-enc.sec.pem")
	if err != nil {
		panic(err)
	}
	writerPrivateKey, err := keys.ReadPrivateKey(keyFile, []byte("123123"))
	if err != nil {
		panic(err)
	}
	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.pub.pem")
	if err != nil {
		panic(err)
	}
	readerPublicKey, err := keys.ReadPublicKey(keyFile)
	if err != nil {
		panic(err)
	}
	writer, err := NewCrypt4GHWriter(&buf, writerPrivateKey, readerPublicKey, nil)
	if err != nil {
		panic(err)
	}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		panic(err)
	}
	err = inFile.Close()
	if err != nil {
		panic(err)
	}
	err = writer.Close()
	if err != nil {
		panic(err)
	}

	keyFile, err = os.Open("../test/crypt4gh-x25519-enc.sec.pem")
	if err != nil {
		panic(err)
	}
	readerSecretKey, err := keys.ReadPrivateKey(keyFile, []byte("password"))
	if err != nil {
		panic(err)
	}
	reader, err := NewCrypt4GHReader(&buf, readerSecretKey, nil)
	if err != nil {
		panic(err)
	}
	discarded, err := reader.Discard(4)
	if err != nil {
		panic(err)
	}
	println(discarded)
	all, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	s := string(all)
	println(s)
}
