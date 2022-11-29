package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/logrusorgru/aurora/v4"
	"golang.org/x/term"
)

// YesNoPrompt asks yes/no questions using a question.
func YesNoPrompt(question string, def bool) bool {
	choices := "Yes/no"
	if !def {
		choices = "yes/No"
	}

	r := bufio.NewReader(os.Stdin)
	var s string

	for {
		fmt.Fprintf(os.Stdout, "%s (%s) ", aurora.Bold(question), aurora.Underline(choices))
		s, _ = r.ReadString('\n')
		s = strings.TrimSpace(s)
		if s == "" {
			return def
		}
		s = strings.ToLower(s)
		if s == "y" || s == "yes" {
			return true
		}
		if s == "n" || s == "no" {
			return false
		}
	}
}

func PasswordPrompt(label string) (string, error) {
	fmt.Fprint(os.Stdout, aurora.Bold(label+" "))
	pwd, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	return string(pwd), err
}
