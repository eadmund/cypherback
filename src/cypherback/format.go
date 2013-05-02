package cypherback

import (
	"compress/lzw"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	//"bufio"
)

type metadata struct {
	path   string
	info   os.FileInfo
	chunks [][]byte
}

/*
emit all path/info tuples

*/

func ProcessPath(path string, secrets *Secrets) (err error) {
	chunks := make(chan []byte)
	metadataChan := make(chan metadata)
	go func() {
		walkfunc, err := makeFileProcessor(secrets, chunks, metadataChan)
		if err == nil {
			filepath.Walk(path, walkfunc)
		}
		close(chunks)
		close(metadataChan)
	}()
	for m := range metadataChan {
		_ = m
		//fmt.Println(m.path, m.info.Size(), m.info.Mode(), m.info.ModTime())
	}
	return nil
}

func makeFileProcessor(secrets *Secrets, chunks chan []byte, metadataChan chan metadata) (filepath.WalkFunc, error) {
	tempDir, err := ioutil.TempDir("/tmp/", "cypherback")
	if err != nil {
		return nil, err
	}
	seenChunks := make(map[string][]byte)
	storageHash := hmac.New(sha512.New384, secrets.chunkStorage)
	return func(path string, info os.FileInfo, err error) error {
		metadataChan <- metadata{path, info, nil}
		//fmt.Println(path, info.Name(), info.Size(), info.Mode(), info.ModTime())
		if info.Size() > 0 && info.Mode()&os.ModeType == 0 {
			fmt.Println(path)
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			chunk := make([]byte, 256*1024)
			for {
				storageHash.Reset()
				n, readErr := file.Read(chunk)
				if n == 0 {
					if err != nil && err != io.EOF {
						return err
					}
					break
				}
				//fmt.Println(chunk[:n])
				_, err = storageHash.Write(chunk[:n])
				if err != nil {
					return err
				}
				storageLoc := storageHash.Sum(nil)
				fmt.Println(hex.EncodeToString(storageLoc))
				//fmt.Println(string(chunk[:n]))
				chunkFile, err := os.Create(tempDir + "/" + hex.EncodeToString(storageLoc))
				if err != nil {
					return err
				}
				defer chunkFile.Close()
				encryptor, err := newEncWriter(chunkFile, secrets)
				if err != nil {
					return err
				}
				defer encryptor.Close()
				compressor := lzw.NewWriter(encryptor, lzw.LSB, 8)
				defer compressor.Close()
				_, err = compressor.Write(chunk[:n])
				if err != nil {
					return err
				}
				seenChunks[string(storageLoc)] = []byte("he")
				if readErr != nil {
					break
				}
			}
			if err != io.EOF {
				return err
			}
		}
		return nil
	}, nil
	//return processFile
}

type encWriter struct {
	writer   io.Writer
	buf      []byte
	cypher   cipher.BlockMode
	authHMAC hash.Hash
}

func (ew encWriter) Write(b []byte) (int, error) {
	ew.buf = append(ew.buf, b...)
	fmt.Println(len(ew.buf))
	ew.authHMAC.Write(b)
	return len(b), nil
}

func (ew encWriter) Close() error {
	b := pad(ew.buf)
	ew.cypher.CryptBlocks(b, b)
	ew.authHMAC.Write(b)
	_, err := ew.writer.Write(b)
	if err != nil {
		return err
	}
	authSum := ew.authHMAC.Sum(nil)
	_, err = ew.writer.Write(authSum)
	return err
}

func newEncWriter(w io.Writer, secrets *Secrets) (*encWriter, error) {
	aesCypher, err := aes.NewCipher(secrets.chunkEncryption)
	if err != nil {
		return nil, err
	}
	cypher := cipher.NewCBCEncrypter(aesCypher, secrets.chunkEncryption)
	authHMAC := hmac.New(sha512.New384, secrets.chunkAuthentication)
	authHMAC.Write([]byte{0}) // file version
	return &encWriter{w, make([]byte, 0), cypher, authHMAC}, nil
}

func pad(b []byte) []byte {
	padLen := -((len(b) % 16) - 16)
	fmt.Println(len(b), padLen)
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(b, padding...)
}
