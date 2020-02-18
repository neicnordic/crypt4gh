package main

import (
	"fmt"
	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora"
	"log"
	"os"
)

const (
	generate = "generate"
	encrypt  = "encrypt"
	decrypt  = "decrypt"
	version  = "version"
)

var generateOptions struct {
	Name     string `short:"n" long:"name" description:"Key pair name" required:"true"`
	Password string `short:"p" long:"password" description:"Private key password (asked interactively later if skipped)"`
}

var generateOptionsParser = flags.NewParser(&generateOptions, flags.None)

var encryptOptions struct {
	FileName          string `short:"f"  long:"file" description:"File to encrypt" value-name:"FILE"`
	SecretKeyFileName string `short:"s" long:"seckey" description:"Secret key to use" value-name:"FILE" required:"true"`
	PublicKeyFileName string `short:"p" long:"pubkey" description:"Public key to use" value-name:"FILE" required:"true"`
}
var encryptOptionsParser = flags.NewParser(&encryptOptions, flags.None)

var decryptOptions struct {
	FileName          string `short:"f" long:"file" description:"File to decrypt" value-name:"FILE" required:"true"`
	SecretKeyFileName string `short:"s" long:"seckey" description:"Secret key to use" value-name:"FILE" required:"true"`
}

var decryptOptionsParser = flags.NewParser(&decryptOptions, flags.None)

func main() {
	args := os.Args
	if len(args) == 1 || args[1] == "-h" || args[1] == "--help" {
		generateOptionsParser.WriteHelp(os.Stdout)
		encryptOptionsParser.WriteHelp(os.Stdout)
		decryptOptionsParser.WriteHelp(os.Stdout)
		os.Exit(0)
	}
	commandName := args[1]
	switch commandName {
	case generate:
		_, err := generateOptionsParser.Parse()
		if err != nil {
			log.Fatal(aurora.Red(err))
		}
		publicKey, privateKey, err := keys.GenerateKeyPair()
		if err != nil {
			log.Fatal(aurora.Red(err))
		}
		fmt.Printf("%v", publicKey)
		fmt.Printf("%v", privateKey)
	case encrypt:
		_, _ = encryptOptionsParser.Parse()
		fmt.Printf("%v", encryptOptions)
	case decrypt:
		_, _ = decryptOptionsParser.Parse()
		fmt.Printf("%v", decryptOptions)
	default:
		log.Fatal(aurora.Red(fmt.Sprintf("command '%v' is not recognized", commandName)))
	}
}
