package cypherback

import (
	"io"
	"math/big"
	"bytes"
	"os"
	"crypto/aes"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"bitbucket.org/taruti/termios"
	"path/filepath"
	"code.google.com/p/go.crypto/pbkdf2"
	//"time"
)

type Secrets struct {
	chunkEncryption []byte
	chunkAuthentication []byte
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

func GenerateSecrets() (err error) {
	if err != nil {
		return err
	}
	secrets := &Secrets{}
	secrets.chunkEncryption, err = genKey(32)
	if err != nil {
		return err
	}
	secrets.chunkAuthentication, err = genKey(32)
	if err != nil {
		return err
	}
	secrets.chunkStorage, err = genKey(32)
	if err != nil {
		return err
	}
	configDir, err := ensureConfigDir()
	if err != nil {
		return err
	}			
	secretsPath := filepath.Join(configDir, "secrets")
	err = writeSecrets(secrets, secretsPath)
	if err != nil {
		return err
	}
	fmt.Println(secrets)

	return nil
}

func writeSecrets(secrets *Secrets, path string) (err error) {
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

	version := []byte{0}
	n, err = file.Write(version)
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("Error writing secrets file")
	}
	authHMAC.Write(version) // per the language docs, hash.Hash.Write never errors

	n, err = file.Write(salt)
	if err != nil {
		return err
	}
	if n != len(salt) {
		return fmt.Errorf("Error writing secrets file")
	}
	authHMAC.Write(salt)

	iterBig := big.NewInt(int64(iterations))
	iterBytes := iterBig.Bytes()
	iterBytes = append(make([]byte, 8-len(iterBytes)), iterBytes...)
	n, err = file.Write(iterBytes)
	if err != nil {
		return err
	}
	if n != len(iterBytes) {
		return fmt.Errorf("Error writing secrets file")
	}
	authHMAC.Write(iterBytes)

	cypher, err := aes.NewCipher(secretsEncKey)
	if err != nil {
		return err
	}
	keyBuf := make([]byte, len(secrets.chunkEncryption))
	cypher.Encrypt(keyBuf, secrets.chunkEncryption)
	cypher.Encrypt(keyBuf[16:], secrets.chunkEncryption[16:])
	n, err = file.Write(keyBuf)
	if err != nil {
		return err
	}
	if n != len(keyBuf) {
		return fmt.Errorf("Error writing secrets file")
	}
	authHMAC.Write(keyBuf)

	keyBuf = make([]byte, len(secrets.chunkAuthentication))
	cypher.Encrypt(keyBuf, secrets.chunkAuthentication)
	cypher.Encrypt(keyBuf[16:], secrets.chunkAuthentication[16:])
	n, err = file.Write(keyBuf)
	if err != nil {
		return err
	}
	if n != len(keyBuf) {
		return fmt.Errorf("Error writing secrets file")
	}
	authHMAC.Write(keyBuf)


	keyBuf = make([]byte, len(secrets.chunkStorage))
	cypher.Encrypt(keyBuf, secrets.chunkStorage)
	cypher.Encrypt(keyBuf[16:], secrets.chunkStorage[16:])
	n, err = file.Write(keyBuf)
	if err != nil {
		return err
	}
	if n != len(keyBuf) {
		return fmt.Errorf("Error writing secrets file")
	}
	authHMAC.Write(keyBuf)
	authSum := authHMAC.Sum(nil)
	n, err = file.Write(authSum)
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
	

	secretsKeys := pbkdf2.Key([]byte(passphrase), salt, iterations, 80, sha512.New384)
	secretsEncKey := secretsKeys[:32]
	secretsAuthKey := secretsKeys[32:]
	authHMAC := hmac.New(sha512.New384, secretsAuthKey)
	authHMAC.Write([]byte{0})
	authHMAC.Write(salt)
	authHMAC.Write(iterBytes)

	cypher, err := aes.NewCipher(secretsEncKey)
	if err != nil {
		return nil, err
	}	

	secrets = &Secrets{}
	secrets.chunkEncryption = make([]byte, 32)
	secrets.chunkAuthentication = make([]byte, 32)
	secrets.chunkStorage = make([]byte, 32)

	keyBuf := make([]byte, len(secrets.chunkEncryption))
	n, err = file.Read(keyBuf)
	if err != nil {
		return nil, err
	}
	if n != len(keyBuf) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	authHMAC.Write(keyBuf)
	cypher.Decrypt(secrets.chunkEncryption, keyBuf)
	cypher.Decrypt(secrets.chunkEncryption[16:], keyBuf[16:])

	keyBuf = make([]byte, len(secrets.chunkAuthentication))
	n, err = file.Read(keyBuf)
	if err != nil {
		return nil, err
	}
	if n != len(keyBuf) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	authHMAC.Write(keyBuf)
	cypher.Decrypt(secrets.chunkAuthentication, keyBuf)
	cypher.Decrypt(secrets.chunkAuthentication[16:], keyBuf[16:])

	keyBuf = make([]byte, len(secrets.chunkStorage))
	n, err = file.Read(keyBuf)
	if err != nil {
		return nil, err
	}
	if n != len(keyBuf) {
		return nil, fmt.Errorf("Error reading secrets file")
	}
	authHMAC.Write(keyBuf)
	cypher.Decrypt(secrets.chunkStorage, keyBuf)
	cypher.Decrypt(secrets.chunkStorage[16:], keyBuf[16:])


	authSum := make([]byte, authHMAC.Size())
	n, err = file.Read(authSum)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != len(authSum) {
		return nil, fmt.Errorf("Error reading secrets file: %d", n)
	}
	if !bytes.Equal(authHMAC.Sum(nil), authSum) {
		return nil, fmt.Errorf("Corrupted secrets file")
	}
	return secrets, nil
}