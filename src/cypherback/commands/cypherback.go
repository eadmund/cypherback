package main

import (
	"cypherback"
	"fmt"
	"os"
)

func die(format string, args ...interface{}) {
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
		dieUsage()
	}
	switch os.Args[1] {
	case "secrets":
		if len(os.Args) < 3 {
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
	case "process":
		if len(os.Args) < 3 {
			dieUsage()
		}
		var paths []string
		paths = append(paths, os.Args[2])

		secrets, err := cypherback.ReadSecrets()
		if err != nil {
			die("Error: %v", err)
		}

		for _, path := range paths {
			cypherback.ProcessPath(path, secrets)
		}	
	default:
		die("Unknown command %s", os.Args[1])
	}

	/**/
}
