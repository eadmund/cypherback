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

package cypherback

import (
	"bytes"
	memoryBackend "cypherback/backends/memory"
	"testing"
)

func TestWriteReadBackupSet(t *testing.T) {
	backend := memoryBackend.New()
	backend.WriteBackupSet("foo", "bar", []byte("barbazquux"))
	data, err := backend.ReadBackupSet("foo", "bar")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("barbazquux")) {
		t.Fatal("Could not read back written backup set")
	}
}

func TestBackupSet(t *testing.T) {
	backend := memoryBackend.New()
	secrets, err := GenerateSecrets(backend)
	defer ZeroSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	set, err := EnsureBackupSet(backend, secrets, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if set == nil {
		t.Fatal("nil")
	}
}
