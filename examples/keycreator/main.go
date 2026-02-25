// package main for keycreator, an example of what a key creator can look like
package main

import (
	"fmt"
	"os"

	"github.com/neicnordic/crypt4gh/keys"
	"golang.org/x/crypto/chacha20poly1305"
)

// usage prints a nice message to instruct the user
func usage(path string) {
	fmt.Printf(`Usage: %s PUBLICKEY PRIVATEKEY PASSWORD
	
Generate a pair of public and privatekey and write the public key to PUBLICKEY
and the private to PRIVATEKEY. PRIVATEKEY will be encrypted with PASSWORD.
`, path)
	os.Exit(0)
}

// getRoot generates a suitable fencing for path traversal. Since this is
// a generic demonstrator, we allow very wide access. Please consider suitable
// fencing for your implementations
func getRoot() (*os.Root, error) {
	root, err := os.OpenRoot("/")

	return root, err
}

// generateAndWriteKeyFiles does the heavy lifting here, generating
// a keypair and writing them to the specified filenames, the
// private key encrypted with password
func generateAndWriteKeyFiles(publicKeyFileName, privateKeyFileName, password string) (err error) {
	publicKey := [chacha20poly1305.KeySize]byte{}
	var privateKey [chacha20poly1305.KeySize]byte

	// Get a keypair
	publicKey, privateKey, err = keys.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("Error while generating key pair: %v", err)
	}

	// Limit for taint handling, since this is an example we're not being
	// overly strict though
	root, err := getRoot()
	if err != nil {
		return fmt.Errorf("Error when opening root: %v", err)
	}

	w, err := root.Create(privateKeyFileName)
	if err != nil {
		return fmt.Errorf("Error when opening private key output %s: %v", privateKeyFileName, err)
	}

	// Write the private key as a crypt4gh x25519 key
	if err := keys.WriteCrypt4GHX25519PrivateKey(w, privateKey, []byte(password)); err != nil {
		return fmt.Errorf("Error when writing private key: %v", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("Error when closing private key file: %v", err)
	}

	w, err = root.Create(publicKeyFileName)
	if err != nil {
		return fmt.Errorf("Error when opening public key output %s: %v", publicKeyFileName, err)
	}

	if err := keys.WriteCrypt4GHX25519PublicKey(w, publicKey); err != nil {
		return fmt.Errorf("Error when closing public key file: %v", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("Error when closing private key file: %v", err)
	}

	fmt.Printf("Wrote public key to %s and private key to %s\n\n", publicKeyFileName, privateKeyFileName)

	return nil
}

// main is the function we start in
func main() {
	args := os.Args

	if len(args) != 4 {
		usage(args[0]) // Won't return
	}

	publicKeyFileName := args[1]
	privateKeyFileName := args[2]
	password := args[3]

	// Use our utility function
	err := generateAndWriteKeyFiles(publicKeyFileName, privateKeyFileName, password)
	if err != nil {
		fmt.Printf("Error during key creation: %v", err)
	}
}
