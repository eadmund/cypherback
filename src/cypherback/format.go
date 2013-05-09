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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
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

// v1: simply make a file info structure for each file or directory
// found, appending to a list which is return; in later versions, do
// smarter things like having workers &c.

func ProcessPath(path string, secrets *Secrets) (err error) {
	backupSet, err := newBackupSet(secrets)
	if err != nil {
		return err
	}
	walkfunc := func(path string, info os.FileInfo, err error) error {
		record, err := backupSet.fileRecordFromFileInfo(path, info)
		if err != nil {
			return err
		}
		backupSet.records = append(backupSet.records, record)
		return nil
	}
	filepath.Walk(path, walkfunc)
	fmt.Println(backupSet)
	return nil
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
	aesCypher, err := aes.NewCipher(secrets.chunkMaster)
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
