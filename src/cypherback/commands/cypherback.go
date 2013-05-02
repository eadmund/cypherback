package main

import (
	"cypherback"
	"os"
	"fmt"
)

func die(format string, args... interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func dieUsage() {
	die(`Usage:
  cyphertite secrets generate [--plaintext-tag TAG]
`)
}

func main() {
	if len(os.Args) < 2 {
		secrets, err := cypherback.ReadSecrets()
		if err != nil {
			die("Error: %v", err)
		}
		fmt.Println(secrets)
		dieUsage()
	}
	if os.Args[1] == "secrets" {
		if len (os.Args) < 3 {
			dieUsage()
		}
		if os.Args[2] == "generate" {
			err := cypherback.GenerateSecrets()
			if err != nil {
				die("Error: %v", err)
			}
		} else {
			die("Unknown secrets command %s", os.Args[2])
		}
	} else {
		die("Unknown command %s", os.Args[1])
	}

	/*var paths []string
	if len(os.Args) == 2 {
		paths = append(paths, os.Args[1])
	} else {
		paths = append(paths, ".")
	}
	for _, path := range paths {
		cypherback.ProcessPath(path)
	}*/
}
