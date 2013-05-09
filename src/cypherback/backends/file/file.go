package file

type FileBackend struct {
	path string
}

func (fb *FileBackend) WriteSecrets(secrets *Secrets) (err error) {

}
