package cypherback

import (
	"bitbucket.org/taruti/termios"
	"bytes"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	//"time"
)

type Secrets struct {
	// AES-256 keys
	chunkEncryption     []byte
	chunkAuthentication []byte
	// HMAC-SHA-384 key
	chunkStorage []byte
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
	secrets.chunkEncryption, err = genKey(32)
	if err != nil {
		return nil, err
	}
	secrets.chunkAuthentication, err = genKey(32)
	if err != nil {
		return nil, err
	}
	secrets.chunkStorage, err = genKey(48)
	if err != nil {
		return nil, err
	}
	return secrets, err
}

func GenerateSecrets() (secrets *Secrets, err error) {
	secrets, err = generateSecrets()
	if err != nil {
		return nil, err
	}
	configDir, err := ensureConfigDir()
	if err != nil {
		return nil, err
	}
	secretsPath := filepath.Join(configDir, "secrets")
	err = writeSecrets(secrets, secretsPath)
	if err != nil {
		return nil, err
	}
	fmt.Println(secrets)

	return secrets, nil
}

func writeSecrets(secrets *Secrets, path string) (err error) {
	/*
		To write a secrets file:

		PBKDF2 the user's password with a random 32-byte salt under SHA-384;
		use this to generate 80 bytes of keying material.  The first 32 bytes
		form an AES-256 encryption key; the next 48 bytes form an HMAC-SHA-384
		authentication key.

		Byte Length
		 00    1    File version (0 for this version)
		 01   32    Salt
		 33    8    Number of PBKDF2 iterations
		 41   32    AES-256-ECB(encryption key, chunk encryption key)
		 73   32    AES-256-ECB(encryption key, chunk authentication key)
		105   48    AES-256-ECB(encryption key, chunk storage key)
		153   48    HMAC-SHA-384(authentication key, bytes 00-152)

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
	authHMAC := hmac.New(sha512.New384, secretsAuthKey)
	// FIXME: write temporary file first
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

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

	cypher, err := aes.NewCipher(secretsEncKey)
	if err != nil {
		return err
	}
	keyBuf := make([]byte, len(secrets.chunkEncryption))
	cypher.Encrypt(keyBuf, secrets.chunkEncryption)
	cypher.Encrypt(keyBuf[16:], secrets.chunkEncryption[16:])
	n, err = writer.Write(keyBuf)
	if err != nil {
		return err
	}
	if n != len(keyBuf) {
		return fmt.Errorf("Error writing secrets file")
	}

	keyBuf = make([]byte, len(secrets.chunkAuthentication))
	cypher.Encrypt(keyBuf, secrets.chunkAuthentication)
	cypher.Encrypt(keyBuf[16:], secrets.chunkAuthentication[16:])
	n, err = writer.Write(keyBuf)
	if err != nil {
		return err
	}
	if n != len(keyBuf) {
		return fmt.Errorf("Error writing secrets file")
	}

	keyBuf = make([]byte, len(secrets.chunkStorage))
	cypher.Encrypt(keyBuf, secrets.chunkStorage)
	cypher.Encrypt(keyBuf[16:], secrets.chunkStorage[16:])
	cypher.Encrypt(keyBuf[32:], secrets.chunkStorage[32:])
	n, err = writer.Write(keyBuf)
	if err != nil {
		return err
	}
	if n != len(keyBuf) {
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

	return nil
}

func ReadSecrets() (secrets *Secrets, err error) {
	configDir, err := ensureConfigDir()
	if err != nil {
		return nil, err
	}
	secretsPath := filepath.Join(configDir, "secrets")
	return readSecrets(secretsPath)
}

func readSecrets(path string) (secrets *Secrets, err error) {
	passphrase := termios.Password("Enter passphrase: ")

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
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
	secretsEncKey := secretsKeys[:32]
	secretsAuthKey := secretsKeys[32:]
	authHMAC := hmac.New(sha512.New384, secretsAuthKey)
	authHMAC.Write([]byte{0})
	authHMAC.Write(salt)
	authHMAC.Write(iterBytes)

	reader := io.TeeReader(file, authHMAC)
	cypher, err := aes.NewCipher(secretsEncKey)
	if err != nil {
		return nil, err
	}

	secrets = &Secrets{}
	secrets.chunkEncryption = make([]byte, 32)
	secrets.chunkAuthentication = make([]byte, 32)
	secrets.chunkStorage = make([]byte, 48)

	keyBuf := make([]byte, len(secrets.chunkEncryption))
	n, err = reader.Read(keyBuf)
	if err != nil {
		return nil, err
	}
	if n != len(keyBuf) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	cypher.Decrypt(secrets.chunkEncryption, keyBuf)
	cypher.Decrypt(secrets.chunkEncryption[16:], keyBuf[16:])

	keyBuf = make([]byte, len(secrets.chunkAuthentication))
	n, err = reader.Read(keyBuf)
	if err != nil {
		return nil, err
	}
	if n != len(keyBuf) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	cypher.Decrypt(secrets.chunkAuthentication, keyBuf)
	cypher.Decrypt(secrets.chunkAuthentication[16:], keyBuf[16:])

	keyBuf = make([]byte, len(secrets.chunkStorage))
	n, err = reader.Read(keyBuf)
	if err != nil {
		return nil, err
	}
	if n != len(keyBuf) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	cypher.Decrypt(secrets.chunkStorage, keyBuf)
	cypher.Decrypt(secrets.chunkStorage[16:], keyBuf[16:])
	cypher.Decrypt(secrets.chunkStorage[32:], keyBuf[32:])

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
