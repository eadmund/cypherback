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

package file

import (
	"cypherback"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type FileBackend struct {
	path string
}

func (fb *FileBackend) WriteSecrets(id string, encSecrets []byte) (err error) {
	path := filepath.Join(fb.path, id)
	err = os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return nil
	}
	path = filepath.Join(path, "secrets")
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// FIXME: write to a temporary file and atomically overwrite original
	n, err := file.Write(encSecrets)
	if err != nil {
		return err
	}
	if n != len(encSecrets) {
		return fmt.Errorf("Did not write all %d bytes, but only %d", len(encSecrets), n)
	}
	// if there isn't a default secrets file, create a symlink to this one
	defaultPath := filepath.Join(fb.path, "defaultSecrets")
	_, err = os.Stat(defaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Symlink(path, defaultPath)
		} else {
			return err
		}
	}
	return nil
}

func (fb *FileBackend) ReadSecrets() (encSecrets []byte, err error) {
	path := filepath.Join(fb.path, "defaultSecrets")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ioutil.ReadAll(file)
}

func (fb *FileBackend) EnsureBackupSet(secrets *cypherback.Secrets, tag string) (b *cypherback.BackupSet, err error) {
	// scan all backup sets to see if any one is the indicated one;
	// if not, create a new one
	// FIXME: someday implement an index
	var setFile string
	path := filepath.Join(fb.path, hex.EncodeToString(secrets.Id()), "sets")
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		os.MkdirAll(path, os.ModePerm)
		info, err = os.Stat(path)
		if err != nil {
			return nil, err
		}
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", path)
	}
	checkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		tagBytes, err := cypherback.ReadTag(file)
		if err != nil {
			return err
		}
		if string(tagBytes) != tag {
			return nil
		}
		setFile = path
		return nil
	}
	err = filepath.Walk(path, checkFunc)
	if err != nil {
		return nil, err
	}
	if setFile == "" {
		// create the backup set file
	}
	return nil, fmt.Errorf("Unimplemented")
}

func NewFileBackend(path string) *FileBackend {
	return &FileBackend{path: path}
}
