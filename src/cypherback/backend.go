package cypherback

type Backend interface {
	WriteSecrets(encSecrets []byte) error
	ReadSecrets() ([]byte, error)
}
