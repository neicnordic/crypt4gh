// package main for reader, an example of what a crypt4gh file reader
// can look like
package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"strconv"

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

// readPrivateKey reads the private key file designated by filename
// encrypted with password, if any.
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

// readFile reads and decrypts
func readFile(filename string, writer io.Writer, readerKey [chacha20poly1305.KeySize]byte, start, end int64) error {

	underReader, err := os.Open(filename)
	if err != nil {
		return err
	}

	defer underReader.Close()

	reader, err := streaming.NewCrypt4GHReader(underReader, readerKey, nil)
	if err != nil {
		return err
	}
	defer reader.Close()

	if start != 0 {
		// We don't want to read from start, skip ahead to where we should be
		if _, err := reader.Seek(start, 0); err != nil {
			return err
		}
	}

	// Calculate how much we should read (if given)
	togo := end - start

	buf := make([]byte, 4096)

	// Loop until we've read what we should (if no/faulty end given, that's EOF)
	for end == 0 || togo > 0 {
		rbuf := buf[:]

		if end != 0 && togo < 4096 {
			// If we don't want to read as much as 4096 bytes
			rbuf = buf[:togo]
		}
		r, err := reader.Read(rbuf)
		togo -= int64(r)

		// Nothing more to read?
		if err == io.EOF && r == 0 {
			// Fall out without error if we had EOF (if we got any data, do one
			// more lap in the loop)
			return nil
		}

		if err != nil && err != io.EOF {
			// An error we want to signal?
			return err
		}

		wbuf := rbuf[:r]
		for len(wbuf) > 0 {
			// Loop until we've written all that we could read,
			// fall out on error
			w, err := writer.Write(wbuf)

			if err != nil {
				return err
			}
			wbuf = wbuf[w:]
		}
	}

	return nil
}

// usage prints a friendly message
func usage(path string) {
	fmt.Printf(`Usage: %s INPUT READERPRIVATEKEY PASSWORD [START [END]]
	
Read and decrypt INPUT (encrypted for the public key corresponding to
READERPRIVATEKEY) and write to stdout.

If start is given, start reading at that offset in the file rather than from
the start. If end is given, stop there (byte at offsent end is not included).

`, path)
	os.Exit(0)
}

// getStartEnd returns the start and end values to use or 0
// if not provided
func getStartEnd(args []string) (start, end int64, err error) {
	if len(args) >= 5 {
		start, err = strconv.ParseInt(args[4], 10, 0)

		if err != nil {
			return 0, 0, fmt.Errorf("Couldn't parse start offset %s as a decimal number: %v", args[4], err)
		}
	}
	if len(args) == 6 {
		end, err = strconv.ParseInt(args[5], 10, 0)
		if err != nil {
			return 0, 0, fmt.Errorf("Couldn't parse end offset %s as a decimal number: %v", args[5], err)
		}
	}

	if end != 0 && end <= start {
		log.Printf("End specified (%d) but before start (%d), ignoring", end, start)
		end = 0
	}

	if end != 0 {
		fmt.Printf("Will start at %d and read to the end.\n", start)
		return start, end, nil
	}

	fmt.Printf("Will start at %d and read to %d.\n", start, end)
	return start, end, nil

}

// main is where we start
func main() {
	args := os.Args

	if len(args) < 4 || len(args) > 6 {
		usage(args[0]) // Won't return
	}

	inputFilename := args[1]
	privateKeyFileName := args[2]
	password := args[3]

	// We need the private key to decrypt the file
	privateKey, err := readPrivateKey(privateKeyFileName, []byte(password))
	if err != nil {
		log.Fatalf("Unexpected error while reading reader key: %v", err)
	}

	fmt.Printf("Will read from %s, decrypt and output to stderr.\n", inputFilename)

	// Pick up start and end if passed (will get 0 otherwise)
	start, end, err := getStartEnd(args)
	if err != nil {
		log.Fatalf("Error while parsing start and end: %v", err)
	}

	err = readFile(inputFilename, os.Stdout, privateKey, start, end)
	if err != nil {
		log.Fatalf("Error while decrypting file %s: %v", inputFilename, err)
	}

}
