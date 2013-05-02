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
	"math/big"
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

Chunk format

Byte Length
  0    1    version (zero for this format)
  1    1    compressed?
  2   16    initialisation vector
 18    4    length
 22    -    AES-256-CTR(chunk encryption key, data)
  -   48    HMAC-SHA-384(chunk authentication key, all preceding bytes)

Each chunk is stored to the backing store under the name
HMAC-SHA-384(chunk storage key, plaintext). 

*/

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
		fmt.Println(path, info)
		if info.Size() > 0 && info.Mode()&os.ModeType == 0 {
			fmt.Println(path)
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			chunk := make([]byte, 256*1024)
			plaintext := io.TeeReader(file, storageHash)
			for {
				storageHash.Reset()
				n, readErr := plaintext.Read(chunk)
				if n == 0 {
					if readErr != nil && readErr != io.EOF {
						return err
					}
					break
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
	cypher   cipher.Stream
	iv       []byte
	authHMAC hash.Hash
}

// FIXME: the semantics of an encWriter are goofy

func (ew encWriter) Write(b []byte) (int, error) {
	ew.buf = append(ew.buf, b...)
	fmt.Println(len(ew.buf))
	ew.authHMAC.Write(b)
	return len(b), nil
}

func (ew encWriter) Close() error {
	writer := io.MultiWriter(ew.writer, ew.authHMAC)
	_, err := writer.Write([]byte{0, 1}) // version, compression always true
	if err != nil {
		return err
	}

	_, err = writer.Write(ew.iv)
	if err != nil {
		return err
	}

	lenBig := big.NewInt(int64(len(ew.buf)))
	lenBytes := lenBig.Bytes()
	lenBytes = append(make([]byte, 4-len(lenBytes)), lenBytes...)
	_, err = writer.Write(lenBytes)
	if err != nil {
		return err
	}

	stream := cipher.StreamWriter{S: ew.cypher, W: writer}
	n, err := stream.Write(ew.buf)
	if err != nil {
		return err
	}
	if n != len(ew.buf) {
		return fmt.Errorf("Out-of-sync keystream")
	}
	authSum := ew.authHMAC.Sum(nil)
	_, err = writer.Write(authSum)
	return err
}

func newEncWriter(w io.Writer, secrets *Secrets) (*encWriter, error) {
	aesCypher, err := aes.NewCipher(secrets.chunkEncryption)
	if err != nil {
		return nil, err
	}
	iv, err := genKey(16)
	if err != nil {
		return nil, err
	}
	cypher := cipher.NewCTR(aesCypher, iv)
	authHMAC := hmac.New(sha512.New384, secrets.chunkAuthentication)
	authHMAC.Write([]byte{0}) // file version
	return &encWriter{w, make([]byte, 0), cypher, iv, authHMAC}, nil
}
