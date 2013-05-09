package file

import (
	"crypto/hmac"
	"crypto/sha512"
	"filepath"
	"io/ioutil"
)

type FileBackend struct {
	path string
}

func (fb *FileBackend) WriteSecrets(encSecrets []bytes) (err error) {
	path := filepath.Join(fb.path, "secrets")
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
	return nil
}

func (fb *FileBackend) ReadSecrets() (encSecrets []byte, err error) {
	path := filepath.Join(fb.path, "secrets")
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
