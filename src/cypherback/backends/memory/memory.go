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

package memory

import (
	"fmt"
)

type MemoryBackend struct {
	secrets        map[string][]byte
	defaultSecrets []byte
	backupSets     map[string][]byte
	chunks         map[string][]byte
}

func New() *MemoryBackend {
	return &MemoryBackend{secrets: make(map[string][]byte),
		backupSets: make(map[string][]byte),
		chunks:     make(map[string][]byte),
	}
}

func (mb *MemoryBackend) WriteSecrets(id string, encSecrets []byte) (err error) {
	mb.secrets[id] = encSecrets
	if mb.defaultSecrets == nil {
		mb.defaultSecrets = encSecrets
	}
	return nil
}

func (mb *MemoryBackend) ReadSecrets() (encSecrets []byte, err error) {
	if mb.defaultSecrets != nil {
		return mb.defaultSecrets, nil
	}
	return nil, fmt.Errorf("No default")
}

func (mb *MemoryBackend) WriteBackupSet(secretsId, id string, data []byte) (err error) {
	mb.backupSets[id] = data
	return nil
}

func (mb *MemoryBackend) ReadBackupSet(secretsId, id string) (data []byte, err error) {
	data, ok := mb.backupSets[id]
	if ok {
		return data, nil
	}
	return nil, fmt.Errorf("Could not retrieve backup set")
}

func (mb *MemoryBackend) WriteChunk(secretsId, id string, data []byte) error {
	mb.chunks[id] = data
	return nil
}

func (mb *MemoryBackend) ReadChunk(secretsId, id string) ([]byte, error) {
	data, ok := mb.chunks[id]
	if ok {
		return data, nil
	}
	return nil, fmt.Errorf("Could not retrieve chunk")
}
