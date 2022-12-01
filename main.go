// Package main is the main package of Crypt4GH command-line tool, containing "generate", "encrypt" and "decrypt"
// commands implementations along with additional helper methods.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/logrusorgru/aurora/v4"
	"github.com/neicnordic/crypt4gh/internal/cli"
	version "github.com/neicnordic/crypt4gh/internal/version"
)

const (
	generate  = "generate"
	encrypt   = "encrypt"
	decrypt   = "decrypt"
	reencrypt = "reencrypt"
)

func main() {
	args := os.Args
	if len(args) == 1 || args[1] == "-h" || args[1] == "--help" {
		fmt.Println(cli.GenerateHelpMessage())
		os.Exit(0)
	}
	if args[1] == "-v" || args[1] == "--version" {
		fmt.Println(version.String())
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
		safeExit := cli.GenerateKeys()
		if safeExit {
			os.Exit(0)
		}

	case encrypt:
		safeExit := cli.EncryptOp(secretKeyPath)
		if safeExit {
			os.Exit(0)
		}

	case decrypt:
		safeExit := cli.DecryptOp(secretKeyPath)
		if safeExit {
			os.Exit(0)
		}
	case reencrypt:
		safeExit := cli.ReencryptOp(secretKeyPath)
		if safeExit {
			os.Exit(0)
		}
	default:
		log.Fatal(aurora.Red(fmt.Sprintf("command '%v' is not recognized", commandName)))
	}
}
