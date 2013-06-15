// Copyright 2013 Robert A. Uhl.  All rights reserved.
//
// This file is part of cypherback.
//
// Cypherback is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Cypherback is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Cypherback.  If not, see <http://www.gnu.org/licenses/>.

package cypherback

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
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

// v1: simply make a file info structure for each file or directory
// found, appending to a list which is return; in later versions, do
// smarter things like having workers &c.

func ProcessPath(backupSet *BackupSet, path string) (err error) {
	walkfunc := func(path string, info os.FileInfo, err error) error {
		record, err := backupSet.fileRecordFromFileInfo(path, info)
		if err != nil {
			return err
		}
		backupSet.records = append(backupSet.records, record)
		return nil
	}
	return filepath.Walk(path, walkfunc)
}

type encWriter struct {
	plaintext    io.Writer
	cyphertext   io.Writer
	authHMAC     hash.Hash
	bytesWritten int32
}

// FIXME: the semantics of an encWriter are goofy

func (ew *encWriter) Write(b []byte) (n int, err error) {
	n, err = ew.cyphertext.Write(b)
	ew.bytesWritten += int32(n)
	return n, err
}

func (ew *encWriter) Close() error {
	hashErr := binary.Write(ew.authHMAC, binary.BigEndian, ew.bytesWritten)
	authSum := ew.authHMAC.Sum(nil)
	_, writeErr := ew.plaintext.Write(authSum)
	var plaintextError, cyphertextError error
	if plaintext, ok := ew.plaintext.(io.ReadCloser); ok {
		plaintextError = plaintext.Close()
	}
	if cyphertext, ok := ew.cyphertext.(io.ReadCloser); ok {
		cyphertextError = cyphertext.Close()
	}
	if hashErr != nil || writeErr != nil || plaintextError != nil || cyphertextError != nil {
		return fmt.Errorf("Closure error")
	}
	return nil
}

func newEncWriter(w io.Writer, secrets *Secrets) (*encWriter, error) {
	nonce, err := genKey(48)
	if err != nil {
		return nil, err
	}
	digester := hmac.New(sha512.New384, secrets.chunkMaster)
	digester.Write([]byte("\000chunk encryption\000"))
	digester.Write(nonce)
	digester.Write([]byte{0x01, 0x80})
	derivedKey := digester.Sum(nil)
	key := derivedKey[0:32]
	iv := derivedKey[32:48]
	aesCypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cypher := cipher.NewCTR(aesCypher, iv)
	authHMAC := hmac.New(sha512.New384, secrets.chunkAuthentication)
	writer := io.MultiWriter(w, authHMAC)
	_, err = writer.Write([]byte{0}) // version
	if err != nil {
		return nil, err
	}

	_, err = writer.Write(nonce)
	if err != nil {
		return nil, err
	}

	authHMAC.Write(key)
	authHMAC.Write(iv)
	stream := cipher.StreamWriter{S: cypher, W: writer}
	n, err := stream.Write([]byte{1}) // compression always true
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("Out-of-sync keystream")
	}

	return &encWriter{writer, stream, authHMAC, 50}, nil
}

type encReader struct {
	source   io.Reader
	reader   io.Reader
	authHMAC hash.Hash
	length   int
	numRead  int
}

func newEncReader(r io.Reader, secrets *Secrets, length int) (reader *encReader, err error) {
	buf := make([]byte, 48)
	n, err := r.Read(buf[:1])
	if n != 1 {
		return nil, fmt.Errorf("Error decoding chunk")
	}
	if err != nil {
		return nil, err
	}
	version := buf[0]
	if version != 0 {
		return nil, fmt.Errorf("Unsupported chunk version %d", version)
	}
	n, err = r.Read(buf)
	if n != 48 {
		return nil, fmt.Errorf("Error decoding chunk")
	}
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 48)
	copy(nonce, buf)
	digester := hmac.New(sha512.New384, secrets.chunkMaster)
	digester.Write([]byte("\000chunk encryption\000"))
	digester.Write(nonce)
	digester.Write([]byte{0x01, 0x80})
	derivedKey := digester.Sum(nil)
	key := derivedKey[0:32]
	iv := derivedKey[32:48]
	aesCypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cypher := cipher.NewCTR(aesCypher, iv)
	authHMAC := hmac.New(sha512.New384, secrets.chunkAuthentication)
	authHMAC.Write([]byte{0})
	authHMAC.Write(nonce)
	authHMAC.Write(key)
	authHMAC.Write(iv)
	cypherStream := cipher.StreamReader{S: cypher, R: io.TeeReader(r, authHMAC)}
	n, err = cypherStream.Read(buf[0:1])
	if n != 1 {
		return nil, fmt.Errorf("Error decoding chunk")
	}
	if err != nil {
		return nil, err
	}
	//compressed_p := buf[0] != 0
	return &encReader{source: r, reader: cypherStream, authHMAC: authHMAC, length: length - 48, numRead: 50}, nil
}

func (r *encReader) Read(buf []byte) (n int, err error) {
	switch {
	case r.numRead == r.length:
		return 0, io.EOF
	case r.numRead+len(buf) > r.length:
		n, err = r.reader.Read(buf[:r.length-r.numRead])
		r.numRead += n
		if err != nil {
			return n, err
		}
		return n, io.EOF
	}
	n, err = r.reader.Read(buf)
	r.numRead += n
	return n, err
}

func (r *encReader) Close() error {
	binary.Write(r.authHMAC, binary.BigEndian, int32(r.length))
	authTag := make([]byte, 48)
	n, err := r.source.Read(authTag)
	if n != 48 {
		return fmt.Errorf("Could not authenticate chunk", n)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(r.authHMAC.Sum(nil), authTag) {
		return fmt.Errorf("Could not authenticate chunk\n%s\n%s", hex.EncodeToString(r.authHMAC.Sum(nil)), hex.EncodeToString(authTag))
	}
	if source, ok := r.source.(io.ReadCloser); ok {
		return source.Close()
	}
	return nil
}

// func (s *Secrets) decodeChunk(cyphertext []byte) (plaintext []byte, err error) {
// 	if cyphertext[0] != 1 {
// 		return nil, fmt.Errorf("Version %d not recognised", cyphertext[0])
// 	}
// 	nonce := cyphertext[1:49]
// 	digester := hmac.New(sha512.New384, secrets.chunkMaster)
// 	digester.Write([]byte("\000chunk encryption\000"))
// 	digester.Write(nonce)
// 	digester.Write([]byte{0x01, 0x80})
// 	derivedKey := digester.Sum(nil)
// 	key := derivedKey[0:32]
// 	iv := derivedKey[32:48]
// 	aesCypher, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	cypher := cipher.NewCTR(aesCypher, iv)
// 	authHMAC := hmac.New(sha512.New384, secrets.chunkAuthentication)
// 	authHMAC.Write([]byte{0}) // file version
// 	authHMAC.Write([]byte{0})
// 	authHMAC.Write(nonce)

// 	reader := cipher.StreamReader{S: cypher, R: bytes.NewReader(cyphertext[49:-48])}
// 	compressedByte := make([]byte, 1)
// 	n, err := reader.Read(compressedByte)
// 	if n != 1 {
// 		return nil, fmt.Errorf("Error decoding chunk")
// 	}
// 	if err != nil {
// 		return nil, err
// 	}
// 	compressedP := compressedByte != 0
// 	authHMAC.Write(compressedP)

// }
