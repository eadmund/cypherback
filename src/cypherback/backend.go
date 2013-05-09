package cypherback

type Backend interface  {
	WriteSecrets(secrets *Secrets, encryptionKey, authenticationKey []byte) error
	ReadSecrets(encryptionKey, authenticationKey []byte) (*Secrets, error)
}
