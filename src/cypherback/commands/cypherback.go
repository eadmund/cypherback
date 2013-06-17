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
	//fileBackend "cypherback/backends/file"
	s3Backend "cypherback/backends/s3"
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
  cypherback secrets generate [--plaintext-tag TAG]
    Generate a new secrets file

  cypherback backup TAG PATH…
    Create a new backup set, or append to the existing backup set TAG

  cypherback list TAG
    List contents of backup set TAG 

  cypherback restore TAG
    Restore backup set TAG
`)
	exitCode = 1
}

func exit() {
	os.Exit(exitCode)
}

func logError(format string, args ...interface{}) {
	log.Printf(format+"\n", args...)
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
	_ = configDir
	//backend := fileBackend.NewFileBackend(configDir)
	backend, err := s3Backend.New(os.Getenv("s3_access_key"), 
		os.Getenv("s3_secret_key"),
		"https://s3.amazonaws.com/",
		"cypherback-default")
	if err != nil {
		logError("Error: %v", err)
		return
	}
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
		tag := os.Args[2]
		var paths []string
		paths = append(paths, os.Args[3:]...)

		secrets, err := cypherback.ReadSecrets(backend)
		defer cypherback.ZeroSecrets(secrets)
		if err != nil {
			logError("Error: %v", err)
			return
		}

		backupSet, err := cypherback.EnsureBackupSet(backend, secrets, tag)
		if err != nil {
			logError("Error: %v", err)
			return
		}

		err = backupSet.StartBackup()
		if err != nil {
			logError("Error: %v", err)
			return
		}
		for _, path := range paths {
			err = cypherback.ProcessPath(backupSet, path)
			if err != nil {
				logError("Error: %v", err)
				return
			}
		}
		err = backupSet.EndBackup()
		if err != nil {
			logError("Error: %v", err)
			return
		}
		err = backupSet.Write(backend)
		if err != nil {
			logError("Error: %v", err)
			return
		}
	case "list":
		if len(os.Args) < 3 {
			usage()
			return
		}
		tag := os.Args[2]

		secrets, err := cypherback.ReadSecrets(backend)
		defer cypherback.ZeroSecrets(secrets)
		if err != nil {
			logError("Error: %v", err)
			return
		}
		backupSet, err := cypherback.ReadBackupSet(backend, secrets, tag)
		if err != nil {
			logError("Error: %v", err)
			return
		}
		backupSet.ListRecords()
	case "restore":
		if len(os.Args) < 3 {
			usage()
			return
		}
		tag := os.Args[2]

		secrets, err := cypherback.ReadSecrets(backend)
		defer cypherback.ZeroSecrets(secrets)
		if err != nil {
			logError("Error: %v", err)
			return
		}
		backupSet, err := cypherback.ReadBackupSet(backend, secrets, tag)
		if err != nil {
			logError("Error: %v", err)
			return
		}
		err = backupSet.Restore(backend)
		if err != nil {
			logError("Error: %v", err)
			return
		}
	default:
		logError("Unknown command %s", os.Args[1])
		return
	}
}
