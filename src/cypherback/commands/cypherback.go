// Copyright 2013 Robert A. Uhl.  All rights reserved.
//
// This file is part of cypherback.
//
// Cypherback is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Cypherback is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Cypherback.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"cypherback"
	fileBackend "cypherback/backends/file"
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
	configDir, err := cypherback.EnsureConfigDir()
	if err != nil {
		logError("Couldn't ensure configuration directory exists: %s", err)
		return
	}
	backend := fileBackend.NewFileBackend(configDir)
	switch os.Args[1] {
	case "secrets":
		if len(os.Args) < 3 {
			usage()
			return
		}
		if os.Args[2] == "generate" {
			secrets, err := cypherback.GenerateSecrets(backend)
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

		secrets, err := cypherback.ReadSecrets(backend)
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
