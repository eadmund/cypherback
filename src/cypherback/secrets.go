package cypherback

import (
	"bitbucket.org/taruti/termios"
	"bytes"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"
	//"time"
)

type Secrets struct {
	// AES-256 keys
	metadataEncryption []byte
	chunkMaster        []byte
	// HMAC-SHA-384 keys
	metadataAuthentication []byte
	chunkAuthentication    []byte
	chunkStorage           []byte
	// 64-bit nonce
	metadataNonce []byte
	// all the above are []byte rather than [32]byte, [48]byte or
	// [8]byte in order to eliminate unnecessary copying, which
	// could lead to unzeroed keys in RAM
}

func genKey(length int) (key []byte, err error) {
	key = make([]byte, length)
	n, err := rand.Reader.Read(key)
	if err != nil {
		return nil, err
	}
	if n != length {
		return nil, fmt.Errorf("Couldn't read enough random bytes")
	}
	return key, nil
}

func generateSecrets() (secrets *Secrets, err error) {
	secrets = &Secrets{}
	secrets.metadataEncryption, err = genKey(32)
	if err != nil {
		return nil, err
	}
	secrets.chunkMaster, err = genKey(32)
	if err != nil {
		return nil, err
	}
	secrets.metadataAuthentication, err = genKey(48)
	if err != nil {
		return nil, err
	}
	secrets.chunkAuthentication, err = genKey(48)
	if err != nil {
		return nil, err
	}
	secrets.chunkStorage, err = genKey(48)
	if err != nil {
		return nil, err
	}
	secrets.metadataNonce, err = genKey(8)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func GenerateSecrets(backend Backend) (secrets *Secrets, err error) {
	secrets, err = generateSecrets()
	if err != nil {
		return nil, err
	}
	err = writeSecrets(secrets, backend)
	if err != nil {
		return nil, err
	}

	return secrets, nil
}

func writeSecrets(secrets *Secrets, backend Backend) (err error) {
	/*
		To write a secrets file:

		PBKDF2 the user's password with a random 32-byte salt
		under SHA-384; use this to generate 80 bytes of keying
		material.  The first 32 bytes form an AES-256
		encryption key; the next 48 bytes form an HMAC-SHA-384
		authentication key.

	*/

	passphrase := termios.PasswordConfirm("Enter passphrase: ", "Repeat passphrase: ")
	salt := make([]byte, 32)
	n, err := rand.Reader.Read(salt)
	if err != nil {
		return err
	}
	if n != 32 {
		return fmt.Errorf("Could not read enough random bytes for salt")
	}
	iterations := 131072 // magic number, about 1 second's worth of time on my lappop
	secretsKeys := pbkdf2.Key([]byte(passphrase), salt, iterations, 80, sha512.New384)
	secretsEncKey := secretsKeys[:32]
	secretsAuthKey := secretsKeys[32:]
	secretsKeysDigest := sha512.New384()
	secretsKeysDigest.Write(secretsKeys)
	secretsKeysHash := secretsKeysDigest.Sum(nil)
	authHMAC := hmac.New(sha512.New384, secretsAuthKey)
	file := bytes.NewBuffer(nil)
	writer := io.MultiWriter(file, authHMAC)
	version := []byte{0}
	n, err = writer.Write(version)
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = writer.Write(salt)
	if err != nil {
		return err
	}
	if n != len(salt) {
		return fmt.Errorf("Error writing secrets file")
	}

	iterBig := big.NewInt(int64(iterations))
	iterBytes := iterBig.Bytes()
	iterBytes = append(make([]byte, 8-len(iterBytes)), iterBytes...)
	n, err = writer.Write(iterBytes)
	if err != nil {
		return err
	}
	if n != len(iterBytes) {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = writer.Write(secretsKeysHash)
	if err != nil {
		return err
	}
	if n != len(secretsKeysHash) {
		return fmt.Errorf("Error writing secrets file")
	}

	iv, err := genKey(16)
	if err != nil {
		return err
	}
	n, err = writer.Write(iv)
	if err != nil {
		return err
	}
	if n != len(iv) {
		return fmt.Errorf("Error writing secrets file")
	}

	cypher, err := aes.NewCipher(secretsEncKey)
	if err != nil {
		return err
	}

	ctrWriter := cipher.StreamWriter{S: cipher.NewCTR(cypher, iv),
		W: writer}

	n, err = ctrWriter.Write(secrets.metadataEncryption)
	if err != nil {
		return err
	}
	if n != len(secrets.metadataEncryption) {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = ctrWriter.Write(secrets.metadataAuthentication)
	if err != nil {
		return err
	}
	if n != len(secrets.metadataAuthentication) {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = ctrWriter.Write(secrets.metadataNonce)
	if err != nil {
		return err
	}
	if n != len(secrets.metadataNonce) {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = ctrWriter.Write(secrets.chunkMaster)
	if err != nil {
		return err
	}
	if n != len(secrets.chunkMaster) {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = ctrWriter.Write(secrets.chunkAuthentication)
	if err != nil {
		return err
	}
	if n != len(secrets.chunkAuthentication) {
		return fmt.Errorf("Error writing secrets file")
	}

	n, err = ctrWriter.Write(secrets.chunkStorage)
	if err != nil {
		return err
	}
	if n != len(secrets.chunkStorage) {
		return fmt.Errorf("Error writing secrets file")
	}

	authSum := authHMAC.Sum(nil)
	n, err = writer.Write(authSum)
	if err != nil {
		return err
	}
	if n != len(authSum) {
		return fmt.Errorf("Error writing secrets file")
	}
	return backend.WriteSecrets(file.Bytes())
}

func ReadSecrets(backend Backend) (secrets *Secrets, err error) {
	passphrase := termios.Password("Enter passphrase: ")

	encSecrets, err := backend.ReadSecrets()
	file := bytes.NewBuffer(encSecrets)
	version := make([]byte, 1)
	n, err := file.Read(version)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	if version[0] != 0 {
		return nil, fmt.Errorf("Cannot read file version %d", version[0])
	}

	salt := make([]byte, 32)
	n, err = file.Read(salt)
	if err != nil {
		return nil, err
	}
	if n != len(salt) {
		return nil, fmt.Errorf("Error reading secrets file")
	}

	iterBytes := make([]byte, 8)
	n, err = file.Read(iterBytes)
	if err != nil {
		return nil, err
	}
	if n != len(iterBytes) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	iterBig := big.NewInt(0)
	iterBig.SetBytes(iterBytes)
	iterations := int(iterBig.Int64())

	// FIXME: add some code to the iterations and rewrite the file
	// if the time to generate a key is too far from the target of 1
	// second
	secretsKeys := pbkdf2.Key([]byte(passphrase), salt, iterations, 80, sha512.New384)
	secretsDigest := sha512.New384()
	// don't need to check for errors, per spec
	secretsDigest.Write(secretsKeys)
	secretsKeysHash := secretsDigest.Sum(nil)
	storedHash := make([]byte, len(secretsKeysHash))
	n, err = file.Read(storedHash)
	if err != nil {
		return nil, err
	}
	if n != len(storedHash) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	if !bytes.Equal(storedHash, secretsKeysHash) {
		return nil, fmt.Errorf("Bad password")
	}

	iv := make([]byte, 16)
	n, err = file.Read(iv)
	if err != nil {
		return nil, err
	}
	if n != len(iv) {
		return nil, fmt.Errorf("Error reading secrets file")
	}

	secretsEncKey := secretsKeys[:32]
	secretsAuthKey := secretsKeys[32:]
	authHMAC := hmac.New(sha512.New384, secretsAuthKey)
	authHMAC.Write(version)
	authHMAC.Write(salt)
	authHMAC.Write(iterBytes)
	authHMAC.Write(secretsKeysHash)
	authHMAC.Write(iv)

	reader := io.TeeReader(file, authHMAC)
	cypher, err := aes.NewCipher(secretsEncKey)
	if err != nil {
		return nil, err
	}
	ctrReader := cipher.StreamReader{S: cipher.NewCTR(cypher, iv),
		R: reader}

	secrets = &Secrets{}
	secrets.metadataEncryption = make([]byte, 32)
	n, err = ctrReader.Read(secrets.metadataEncryption)
	if err != nil {
		ZeroSecrets(secrets)
		return nil, err
	}
	if n != len(secrets.metadataEncryption) {
		ZeroSecrets(secrets)
		return nil, fmt.Errorf("Error reading secrets file")
	}
	secrets.metadataAuthentication = make([]byte, 48)
	n, err = ctrReader.Read(secrets.metadataAuthentication)
	if err != nil {
		ZeroSecrets(secrets)
		return nil, err
	}
	if n != len(secrets.metadataAuthentication) {
		ZeroSecrets(secrets)
		return nil, fmt.Errorf("Error reading secrets file")
	}
	secrets.metadataNonce = make([]byte, 8)
	n, err = ctrReader.Read(secrets.metadataNonce)
	if err != nil {
		ZeroSecrets(secrets)
		return nil, err
	}
	if n != len(secrets.metadataNonce) {
		ZeroSecrets(secrets)
		return nil, fmt.Errorf("Error reading secrets file")
	}
	secrets.chunkMaster = make([]byte, 32)
	n, err = ctrReader.Read(secrets.chunkMaster)
	if err != nil {
		ZeroSecrets(secrets)
		return nil, err
	}
	if n != len(secrets.chunkMaster) {
		ZeroSecrets(secrets)
		return nil, fmt.Errorf("Error reading secrets file")
	}
	secrets.chunkAuthentication = make([]byte, 48)
	n, err = ctrReader.Read(secrets.chunkAuthentication)
	if err != nil {
		ZeroSecrets(secrets)
		return nil, err
	}
	if n != len(secrets.chunkAuthentication) {
		ZeroSecrets(secrets)
		return nil, fmt.Errorf("Error reading secrets file")
	}
	secrets.chunkStorage = make([]byte, 48)
	n, err = ctrReader.Read(secrets.chunkStorage)
	if err != nil {
		ZeroSecrets(secrets)
		return nil, err
	}
	if n != len(secrets.chunkStorage) {
		ZeroSecrets(secrets)
		return nil, fmt.Errorf("Error reading secrets file")
	}

	calcSum := authHMAC.Sum(nil)
	authSum := make([]byte, authHMAC.Size())
	n, err = reader.Read(authSum)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != len(authSum) {
		return nil, fmt.Errorf("Error reading secrets file: %d", n)
	}
	if !bytes.Equal(calcSum, authSum) {
		return nil, fmt.Errorf("Corrupted secrets file")
	}
	return secrets, nil
}

// ZeroSecrets zeros out all non-nil keys in SECRETS.
func ZeroSecrets(secrets *Secrets) {
	// don't need to zero out a nil secrets set
	if secrets == nil {
		return
	}
	if secrets.metadataEncryption != nil {
		zeroKey(secrets.metadataEncryption, 32, "metadata encryption key")
		secrets.metadataEncryption = nil
	}
	if secrets.chunkMaster != nil {
		zeroKey(secrets.chunkMaster, 32, "chunk encryption key")
		secrets.chunkMaster = nil
	}
	if secrets.metadataAuthentication != nil {
		zeroKey(secrets.metadataAuthentication, 48, "metadata authentication key")
		secrets.metadataAuthentication = nil
	}
	if secrets.chunkAuthentication != nil {
		zeroKey(secrets.chunkAuthentication, 48, "chunk authentication key")
		secrets.chunkAuthentication = nil
	}
	if secrets.chunkStorage != nil {
		zeroKey(secrets.chunkStorage, 48, "chunk storage")
		secrets.chunkStorage = nil
	}
	if secrets.metadataNonce != nil {
		zeroKey(secrets.metadataNonce, 8, "metadata nonce")
		secrets.metadataNonce = nil
	}
	return
}

// zero out a byte array which should be LENGTH bytes long; if it's not
// then panic with an error
func zeroKey(key []byte, length int, description string) {
	if len(key) != length {
		// FIXME: is panicing the right thing to do here?  It
		// prevents further zeroing.  Perhaps it should be
		// logged, to allow completiong of zeroing.
		panic(fmt.Errorf("SERIOUS ERROR: %s is %d bytes, not %d bytes.  Destroy all items encrypted under this scheme.", description, len(key), length))
	}
	for i := 0; i < length; i++ {
		key[i] = 0
	}
}

func SecretsId(secrets *Secrets) []byte {
	digester := sha512.New384()
	// no errors are possible from hash.Write, per the docs
	digester.Write([]byte("cypherback\x00"))
	digester.Write(secrets.metadataEncryption)
	digester.Write(secrets.metadataAuthentication)
	digester.Write(secrets.metadataNonce)
	digester.Write(secrets.chunkMaster)
	digester.Write(secrets.chunkAuthentication)
	digester.Write(secrets.chunkStorage)
	return digester.Sum(nil)
}
