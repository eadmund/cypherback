package cypherback

import (
	memoryBackend "cypherback/backends/memory"
	"testing"
)

func TestGenerateSecrets(t *testing.T) {
	backend := memoryBackend.New()
	secrets, err := GenerateSecrets(backend)
	defer ZeroSecrets(secrets)
	if err != nil {
		t.Error(err)
	}
}
