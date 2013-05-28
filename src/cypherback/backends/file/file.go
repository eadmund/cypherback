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

func NewFileBackend(path string) *FileBackend {
	return &FileBackend{path: path}
}

func (fb *FileBackend) WriteBackupSet(id string, data []byte) (err error) {
	path := filepath.Join(fb.path, "sets")
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		os.MkdirAll(path, os.ModePerm)
		info, err = os.Stat(path)
		if err != nil {
			return err
		}
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	path = filepath.Join(path, id)
	info, err = os.Stat(path)
	if os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
		n, err := file.Write(data)
		if n != len(data) {
			return fmt.Errorf("Couldn't write all data")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (fb *FileBackend) ReadBackupSet(id string) (data []byte, err error) {
	path := filepath.Join(fb.path, "sets", id)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err = ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}
