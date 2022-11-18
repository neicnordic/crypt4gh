// Package main is the main package of Crypt4GH command-line tool, containing "generate", "encrypt" and "decrypt"
// commands implementations along with additional helper methods.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora"
	"github.com/manifoldco/promptui"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"golang.org/x/crypto/chacha20poly1305"
)

type writeKeys func(writer io.Writer, key [32]byte) error
type writeKeysPassword func(writer io.Writer, key [32]byte, password []byte) error

var (
	version = "dev"
	date    = "unknown"
)

const (
	generate  = "generate"
	encrypt   = "encrypt"
	decrypt   = "decrypt"
	reencrypt = "reencrypt"
)

var generateOptions struct {
	Name     string `short:"n" long:"name" description:"Key pair name" required:"true"`
	Format   string `short:"f" long:"format" description:"Key pair format" choice:"openssl" choice:"crypt4gh" default:"crypt4gh"`
	Password string `short:"p" long:"password" description:"Password to lock Crypt4GH private key (will be prompted afterwords if skipped)"`
}

var generateOptionsParser = flags.NewParser(&generateOptions, flags.None)

var encryptOptions struct {
	FileName          string   `short:"f"  long:"file" description:"File to encrypt" value-name:"FILE" required:"true"`
	PublicKeyFileName []string `short:"p" long:"pubkey" description:"Public key(s) to use" value-name:"FILE" required:"true"`
	SecretKeyFileName string   `short:"s" long:"seckey" description:"Secret key to use" value-name:"FILE"`
}

var encryptOptionsParser = flags.NewParser(&encryptOptions, flags.None)

var decryptOptions struct {
	FileName          string `short:"f" long:"file" description:"File to decrypt" value-name:"FILE" required:"true"`
	SecretKeyFileName string `short:"s" long:"seckey" description:"Secret key to use" value-name:"FILE"`
}

var decryptOptionsParser = flags.NewParser(&decryptOptions, flags.None)

const (
	usageString        = "Usage:\n  crypt4gh\n"
	applicationOptions = "Application Options"
)

var reencryptOptionsParser = flags.NewParser(&reencryptOptions, flags.None)

var reencryptOptions struct {
	FileName          string   `short:"f" long:"file" description:"Input File to re-encrypt" value-name:"FILE" required:"true"`
	OutFileName       string   `short:"o" long:"out" description:"Output File to after re-encrypt" value-name:"FILE" required:"true"`
	PublicKeyFileName []string `short:"p" long:"pubkey" description:"Public key(s) to use" value-name:"FILE" required:"true"`
	SecretKeyFileName string   `short:"s" long:"seckey" description:"Secret key to use" value-name:"FILE"`
}

func main() {
	args := os.Args
	if len(args) == 1 || args[1] == "-h" || args[1] == "--help" {
		fmt.Println(generateHelpMessage())
		os.Exit(0)
	}
	if args[1] == "-v" || args[1] == "--version" {
		fmt.Println(aurora.Blue(version))
		fmt.Println(aurora.Yellow(date))
		os.Exit(0)
	}
	secretKeyPath := os.Getenv("C4GH_SECRET_KEY")
	if secretKeyPath != "" {
		fmt.Print("Using secret key from C4GH_SECRET_KEY: ")
		fmt.Println(aurora.Underline(secretKeyPath))
	}
	commandName := args[1]
	switch commandName {
	case generate:
		safeExit := generateKeys()
		if safeExit {
			os.Exit(0)
		}

	case encrypt:
		safeExit := encryptOp(secretKeyPath)
		if safeExit {
			os.Exit(0)
		}

	case decrypt:
		safeExit := decryptOp(secretKeyPath)
		if safeExit {
			os.Exit(0)
		}
	case reencrypt:
		safeExit := reencryptOp(secretKeyPath)
		if safeExit {
			os.Exit(0)
		}
	default:
		log.Fatal(aurora.Red(fmt.Sprintf("command '%v' is not recognized", commandName)))
	}
}

func readPublicKey(fileName string) (publicKey [chacha20poly1305.KeySize]byte, err error) {
	var publicKeyFile *os.File
	publicKeyFile, err = os.Open(fileName)
	if err != nil {
		return
	}
	return keys.ReadPublicKey(publicKeyFile)
}

func readPrivateKey(fileName string) (privateKey [chacha20poly1305.KeySize]byte, err error) {
	var secretKeyFile *os.File
	secretKeyFile, err = os.Open(fileName)
	if err != nil {
		return
	}
	privateKey, err = keys.ReadPrivateKey(secretKeyFile, nil)
	if err != nil {
		var password string
		password, err = promptPassword("Enter the password to unlock the key")
		if err != nil {
			return
		}
		err = secretKeyFile.Close()
		if err != nil {
			return
		}
		secretKeyFile, _ = os.Open(fileName)
		privateKey, err = keys.ReadPrivateKey(secretKeyFile, []byte(password))
		if err != nil {
			return
		}
	}
	return
}

func writeKeyPair(name string, publicKey, privateKey [chacha20poly1305.KeySize]byte, format, password string) error {

	if format == "openssl" {

		err := writeOpensslKeyPair(name, keys.WriteOpenSSLX25519PublicKey, keys.WriteOpenSSLX25519PrivateKey, publicKey, privateKey)
		if err != nil {
			return err
		}
	} else {
		err := writeCrypt4GHKeyPair(name, keys.WriteCrypt4GHX25519PublicKey, keys.WriteCrypt4GHX25519PrivateKey, publicKey, privateKey, password)
		if err != nil {
			return err
		}

	}
	return nil
}

func writeOpensslKeyPair(name string, publicOp, privateOp writeKeys, publicKey, privateKey [chacha20poly1305.KeySize]byte) error {
	publicKeyFileName := name + ".pub.pem"
	privateKeyFileName := name + ".sec.pem"

	publicKeyFile, err := os.Create(publicKeyFileName)
	if err != nil {
		return err
	}
	if err = publicOp(publicKeyFile, publicKey); err != nil {
		return err
	}
	if err = publicKeyFile.Close(); err != nil {
		return err
	}

	privateKeyFile, err := os.Create(privateKeyFileName)
	if err != nil {
		return err
	}
	if err = privateOp(privateKeyFile, privateKey); err != nil {
		return err
	}

	return privateKeyFile.Close()
}

func writeCrypt4GHKeyPair(name string, publicOp writeKeys, privateOp writeKeysPassword, publicKey, privateKey [chacha20poly1305.KeySize]byte, password string) error {
	publicKeyFileName := name + ".pub.pem"
	privateKeyFileName := name + ".sec.pem"

	publicKeyFile, err := os.Create(publicKeyFileName)
	if err != nil {
		return err
	}
	if err = publicOp(publicKeyFile, publicKey); err != nil {
		return err
	}
	if err = publicKeyFile.Close(); err != nil {
		return err
	}

	privateKeyFile, err := os.Create(privateKeyFileName)
	if err != nil {
		return err
	}
	if password == "" {
		password, err = promptPassword("Enter the password to lock the key")
		if err != nil {
			return err
		}
	}
	if err = privateOp(privateKeyFile, privateKey, []byte(password)); err != nil {
		return err
	}

	return privateKeyFile.Close()
}

func promptYesNo(message string) bool {
	prompt := promptui.Select{
		Label: message,
		Items: []string{"Yes", "No"},
	}
	_, result, err := prompt.Run()
	if err != nil || result != "Yes" {
		return true
	}

	return false
}

func promptPassword(message string) (password string, err error) {
	prompt := promptui.Prompt{
		Label: message,
		Mask:  '*',
	}
	return prompt.Run()
}

func fileExists(fileName string) bool {
	info, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func generateHelpMessage() string {
	header := "crypt4gh [generate | encrypt | decrypt | reencrypt] <args>\n"

	buffer := bytes.Buffer{}
	generateOptionsParser.WriteHelp(&buffer)
	generateUsage := buffer.String()
	generateUsage = strings.Replace(generateUsage, usageString, "", 1)
	generateUsage = strings.Replace(generateUsage, applicationOptions, " "+generate, 1)

	buffer.Reset()
	encryptOptionsParser.WriteHelp(&buffer)
	encryptUsage := buffer.String()
	encryptUsage = strings.Replace(encryptUsage, usageString, "", 1)
	encryptUsage = strings.Replace(encryptUsage, applicationOptions, " "+encrypt, 1)

	buffer.Reset()
	decryptOptionsParser.WriteHelp(&buffer)
	decryptUsage := buffer.String()
	decryptUsage = strings.Replace(decryptUsage, usageString, "", 1)
	decryptUsage = strings.Replace(decryptUsage, applicationOptions, " "+decrypt, 1)

	buffer.Reset()
	reencryptOptionsParser.WriteHelp(&buffer)
	reencryptUsage := buffer.String()
	reencryptUsage = strings.Replace(reencryptUsage, usageString, "", 1)
	reencryptUsage = strings.Replace(reencryptUsage, applicationOptions, " "+reencrypt, 1)

	env := "\n Environment variables:\n\n C4GH_SECRET_KEY\tIf defined, it will be used as the secret key file if parameter not set"

	return header + generateUsage + encryptUsage + decryptUsage + reencryptUsage + env
}

func generateKeys() bool {
	_, err := generateOptionsParser.Parse()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	if fileExists(generateOptions.Name+".pub.pem") || fileExists(generateOptions.Name+".sec.pem") {
		safeExit := promptYesNo(fmt.Sprintf("Key pair with name '%v' seems to already exist. Please, confirm overwriting", generateOptions.Name))

		if safeExit {
			return true
		}
	} else {
		err = writeKeyPair(generateOptions.Name, publicKey, privateKey, generateOptions.Format, generateOptions.Password)
		if err != nil {
			fmt.Println(aurora.Red(err))
			return false
		}
	}
	return false
}

func encryptOp(secretKeyPath string) bool {
	_, err := encryptOptionsParser.Parse()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}

	pubkeyList := [][chacha20poly1305.KeySize]byte{}
	for _, pubkey := range encryptOptions.PublicKeyFileName {
		publicKey, err := readPublicKey(pubkey)
		if err != nil {
			fmt.Println(aurora.Red(err))
			return false
		}
		pubkeyList = append(pubkeyList, publicKey)
	}
	var privateKey [32]byte
	if encryptOptions.SecretKeyFileName == "" && secretKeyPath == "" {
		safeExit := promptYesNo("Secret key not specified and will be autogenerated. Do you want to continue?")

		if safeExit {
			return true
		}
		_, privateKey, err = keys.GenerateKeyPair()

	} else if encryptOptions.SecretKeyFileName != "" {
		privateKey, err = readPrivateKey(encryptOptions.SecretKeyFileName)
	} else {
		privateKey, err = readPrivateKey(secretKeyPath)
	}
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}

	safeExit := encryptFile(privateKey, pubkeyList)

	return safeExit
}

func encryptFile(privateKey [32]byte, pubkeyList [][32]byte) bool {
	inFile, err := os.Open(encryptOptions.FileName)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	outFileName := encryptOptions.FileName + ".c4gh"
	if fileExists(outFileName) {
		safeExit := promptYesNo(fmt.Sprintf("File with name '%v' already exists. Please, confirm overwriting", outFileName))

		if safeExit {
			return true
		}
	}
	outFile, err := os.Create(outFileName)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	crypt4GHWriter, err := streaming.NewCrypt4GHWriter(outFile, privateKey, pubkeyList, nil)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	written, err := io.Copy(crypt4GHWriter, inFile)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = inFile.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = crypt4GHWriter.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = outFile.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	fmt.Println(aurora.Green(fmt.Sprintf("Success! %v bytes encrypted, file name: %v", written, outFileName)))
	return false
}

func decryptOp(secretKeyPath string) bool {
	_, err := decryptOptionsParser.Parse()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	var privateKey [32]byte
	if decryptOptions.SecretKeyFileName == "" && secretKeyPath == "" {
		fmt.Println(aurora.Red("Neither -sk option, nor C4GH_SECRET_KEY env var specified, aborting..."))
		return false
	} else if decryptOptions.SecretKeyFileName != "" {
		privateKey, err = readPrivateKey(decryptOptions.SecretKeyFileName)
	} else {
		privateKey, err = readPrivateKey(secretKeyPath)
	}
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	inFile, err := os.Open(decryptOptions.FileName)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	var outFileName string
	if strings.HasSuffix(decryptOptions.FileName, ".c4gh") {
		outFileName = strings.TrimSuffix(decryptOptions.FileName, ".c4gh")
	} else {
		outFileName = decryptOptions.FileName + ".dec"
	}
	if fileExists(outFileName) {
		safeExit := promptYesNo(fmt.Sprintf("File with name '%v' already exists. Please, confirm overwriting", outFileName))

		if safeExit {
			return true
		}
	}
	outFile, err := os.Create(outFileName)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	crypt4GHReader, err := streaming.NewCrypt4GHReader(inFile, privateKey, nil)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	written, err := io.Copy(outFile, crypt4GHReader)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = inFile.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = outFile.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	fmt.Println(aurora.Green(fmt.Sprintf("Success! %v bytes decrypted, file name: %v", written, outFileName)))
	return false
}

func reencryptOp(secretKeyPath string) bool {
	_, err := reencryptOptionsParser.Parse()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}

	pubkeyList := [][chacha20poly1305.KeySize]byte{}
	for _, pubkey := range reencryptOptions.PublicKeyFileName {
		publicKey, err := readPublicKey(pubkey)
		if err != nil {
			fmt.Println(aurora.Red(err))
			return false
		}
		pubkeyList = append(pubkeyList, publicKey)
	}

	var privateKey [32]byte
	if reencryptOptions.SecretKeyFileName == "" && secretKeyPath == "" {
		fmt.Println(aurora.Red("Neither -sk option, nor C4GH_SECRET_KEY env var specified, aborting..."))
		return false
	} else if reencryptOptions.SecretKeyFileName != "" {
		privateKey, err = readPrivateKey(reencryptOptions.SecretKeyFileName)
	} else {
		privateKey, err = readPrivateKey(secretKeyPath)
	}
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}

	safeExit := reencryptFile(privateKey, pubkeyList)

	return safeExit
}

func reencryptFile(privateKey [32]byte, pubkeyList [][32]byte) bool {
	inFile, err := os.Open(reencryptOptions.FileName)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	outFileName := reencryptOptions.OutFileName
	if fileExists(outFileName) {
		safeExit := promptYesNo(fmt.Sprintf("File with name '%v' already exists. Please, confirm overwriting", outFileName))

		if safeExit {
			return true
		}
	}
	outFile, err := os.Create(outFileName)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	reencryptedFile, err := streaming.ReCrypt4GHWriter(inFile, privateKey, pubkeyList)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	written, err := io.Copy(outFile, reencryptedFile)
	// written, err := reencryptedFile.WriteTo(outFile)
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = inFile.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	err = outFile.Close()
	if err != nil {
		fmt.Println(aurora.Red(err))
		return false
	}
	fmt.Println(aurora.Green(fmt.Sprintf("Success! %v bytes encrypted, file name: %v", written, outFileName)))
	return false
}
