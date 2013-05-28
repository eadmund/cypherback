package cypherback

import (
	"bytes"
	memoryBackend "cypherback/backends/memory"
	"testing"
)

func TestWriteReadBackupSet(t *testing.T) {
	backend := memoryBackend.New()
	backend.WriteBackupSet("foo", []byte("barbazquux"))
	data, err := backend.ReadBackupSet("foo")
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
	set, err := EnsureBackupSet(secrets, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if set == nil {
		t.Fatal("nil")
	}
}
