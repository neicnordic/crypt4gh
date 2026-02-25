// package main for writer, an example of what a crypt4gh file writer can look like
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"regexp"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"golang.org/x/crypto/chacha20poly1305"
)

// getRoot generates a suitable fencing for path traversal. Since this is
// a generic demonstrator, we allow very wide access. Please consider suitable
// fencing for your implementations
func getRoot() (*os.Root, error) {
	root, err := os.OpenRoot("/")

	return root, err
}

// readPublicKey reads the public key from filename and returns the key
// and/or any error encountered.
func readPublicKey(filename string) ([chacha20poly1305.KeySize]byte, error) {
	var key [chacha20poly1305.KeySize]byte

	root, err := getRoot()
	if err != nil {
		return key, err
	}

	reader, err := root.Open(filename)
	if err != nil {
		return key, err
	}

	defer reader.Close() // nolint:errcheck

	key, err = keys.ReadPublicKey(reader)

	return key, err
}

// readPrivateKey reads the private key from filename, possibly decrypts it
// (if password is supplied) and returns the key and/or any error encountered.
func readPrivateKey(filename string, password []byte) ([chacha20poly1305.KeySize]byte, error) {
	var key [chacha20poly1305.KeySize]byte

	root, err := getRoot()
	if err != nil {
		return key, err
	}

	reader, err := root.Open(filename)
	if err != nil {
		return key, err
	}

	defer reader.Close() // nolint:errcheck

	key, err = keys.ReadPrivateKey(reader, password)

	return key, err
}

// writeFile reads from the supplied reader and writes to filename
// as a stream encrypted for readerKey, using writerKey
func writeFile(reader io.Reader, writerKey, readerKey [chacha20poly1305.KeySize]byte, filename string) error {

	root, err := getRoot()
	if err != nil {
		return err
	}

	underWriter, err := root.Create(filename)
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

// cleanPrintable removes any non-printable chars in the string
func cleanPrintable(s string) string {
	r := regexp.MustCompile("[:print:]*")

	print := r.Find([]byte(s))
	if print == nil {
		return ""
	}

	return string(print)
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
		log.Fatalf("Error from writing encrypted file %s: %v", cleanPrintable(outputFilename), err) // #nosec G706
	}
}
