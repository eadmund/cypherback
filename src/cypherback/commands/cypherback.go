package main

import (
	"cypherback"
	"fmt"
	"log"
	"os"
)

var exitCode int

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  cyphertite secrets generate [--plaintext-tag TAG]
`)
	exitCode = 1
}

func exit() {
	os.Exit(exitCode)
}

func logError(format string, args ...interface{}) {
	log.Printf(format, args...)
	exitCode = 1
}

func main() {
	defer exit()

	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "secrets":
		if len(os.Args) < 3 {
			usage()
			return
		}
		if os.Args[2] == "generate" {
			secrets, err := cypherback.GenerateSecrets()
			defer cypherback.ZeroSecrets(secrets)
			if err != nil {
				logError("Error: %v", err)
				return
			}
		} else {
			logError("Unknown secrets command %s", os.Args[2])
			return
		}
	case "backup":
		if len(os.Args) < 4 {
			usage()
			return
		}
		setName := os.Args[2]
		var paths []string
		paths = append(paths, os.Args[3:]...)

		secrets, err := cypherback.ReadSecrets()		
		defer cypherback.ZeroSecrets(secrets)
		if err != nil {
			logError("Error: %v", err)
			return
		}

		_, err = cypherback.EnsureSet(secrets, setName)
		
		if err != nil {
			logError("Error: %v", err)
			return
		}

		for _, path := range paths {
			cypherback.ProcessPath(path, secrets)
		}	
	default:
		logError("Unknown command %s", os.Args[1])
		return
	}
}
