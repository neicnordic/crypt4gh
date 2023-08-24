// package main for writer, an example of what a crypt4gh file writer can look like
package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"golang.org/x/crypto/chacha20poly1305"
)

// readPublicKey reads the public key from filename and returns the key
// and/or any error encountered.
func readPublicKey(filename string) ([chacha20poly1305.KeySize]byte, error) {
	reader, err := os.Open(filename)

	if err != nil {
		var nilKey [chacha20poly1305.KeySize]byte
		return nilKey, err
	}

	key, err := keys.ReadPublicKey(reader)
	reader.Close()
	return key, err
}

// readPrivateKey reads the private key from filename, possibly decrypts it
// (if password is supplied) and returns the key and/or any error encountered.
func readPrivateKey(filename string, password []byte) ([chacha20poly1305.KeySize]byte, error) {
	reader, err := os.Open(filename)

	if err != nil {
		var nilKey [chacha20poly1305.KeySize]byte
		return nilKey, err
	}

	key, err := keys.ReadPrivateKey(reader, password)
	reader.Close()
	return key, err
}

// writeFile reads from the supplied reader and writes to filename
// as a stream encrypted for readerKey, using writerKey
func writeFile(reader io.Reader, writerKey, readerKey [chacha20poly1305.KeySize]byte, filename string) error {

	underWriter, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer underWriter.Close()

	readerPublicKeyList := [][chacha20poly1305.KeySize]byte{readerKey}
	readerPublicKeyList = append(readerPublicKeyList, readerKey)
	writer, err := streaming.NewCrypt4GHWriter(underWriter, writerKey, readerPublicKeyList, nil)
	if err != nil {
		return err
	}

	if _, err = io.Copy(writer, reader); err != nil {
		return err
	}
	return nil
}

func usage(path string) {
	fmt.Printf(`Usage: %s OUTPUT READERPUBLICKEY WRITERPRIVATEKEY PASSWORD
	
Create OUTPUT and wite stdin as a crypt4gh encrypted file, encrypted for
READERPUBLICKEY with WRITERPRIVATEKEY.

`, path)
	os.Exit(0)
}

func main() {
	args := os.Args

	if len(args) == 1 {
		usage(args[0]) // Won't return
	}

	outputFilename := args[1]
	publicKeyFileName := args[2]
	privateKeyFileName := args[3]
	password := args[4]

	var err error
	publicKey, err := readPublicKey(publicKeyFileName)
	if err != nil {
		log.Fatalf("Unexpected error while reading receiver key: %v", err)
	}

	privateKey, err := readPrivateKey(privateKeyFileName, []byte(password))
	if err != nil {
		log.Fatalf("Unexpected error while reading sender key: %v", err)
	}

	fmt.Printf("Will write stdin to %s close when done (e.g. Ctrl-D)\n\n", outputFilename)
	err = writeFile(os.Stdin, privateKey, publicKey, outputFilename)
	if err != nil {
		log.Fatalf("Error from writing encrypted file %s: %v", outputFilename, err)
	}
}
