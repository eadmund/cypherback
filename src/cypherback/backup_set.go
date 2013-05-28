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

// A backup set is really just a metadata file; the chunks for its
// component files are stored separately.
package cypherback

import (
	"bytes"
	"compress/lzw"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
)

type devInode struct {
	dev   uint64
	inode uint64
}

type BackupSet struct {
	tag        string
	secrets    *Secrets
	records    []fileRecord
	hardLinks  map[devInode]string
	seenChunks map[string]bool
	tempDir    string
}

func newBackupSet(tag string, secrets *Secrets) (backupSet *BackupSet, err error) {
	backupSet = &BackupSet{tag: tag, secrets: secrets}
	backupSet.hardLinks = make(map[devInode]string)
	backupSet.seenChunks = make(map[string]bool)
	backupSet.tempDir, err = ioutil.TempDir("/tmp/", "cypherback")
	if err != nil {
		return nil, err
	}
	return backupSet, nil
}

type startRecord struct {
	date   int64
	length uint32
}

func (r *startRecord) Record() (recordType uint8, data []byte) {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, r.date)
	binary.Write(writer, binary.BigEndian, r.length)
	return 0, writer.Bytes()
}

func (r *startRecord) Len() int {
	return 8 + 4
}

type fileRecord interface {
	Record() (recordType uint8, data []byte)
	Len() int
}

// FIXME: handle extended attributes

type baseFileInfo struct {
	name      string
	mode      os.FileMode
	userName  string
	groupName string
	uid       uint32
	gid       uint32
	aTime     time.Time
	mTime     time.Time
	cTime     time.Time
}

func (r *baseFileInfo) Record() []byte {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, int64(r.mode))
	binary.Write(writer, binary.BigEndian, int64(r.uid))
	binary.Write(writer, binary.BigEndian, int64(r.gid))
	binary.Write(writer, binary.BigEndian, int64(r.aTime.UnixNano()))
	binary.Write(writer, binary.BigEndian, int64(r.mTime.UnixNano()))
	binary.Write(writer, binary.BigEndian, int64(r.cTime.UnixNano()))
	binary.Write(writer, binary.BigEndian, int32(len(r.name)))
	writer.Write([]byte(r.name))
	binary.Write(writer, binary.BigEndian, int32(len(r.userName)))
	writer.Write([]byte(r.userName))
	binary.Write(writer, binary.BigEndian, int32(len(r.groupName)))
	writer.Write([]byte(r.groupName))
	return writer.Bytes()
}

func (r *baseFileInfo) Len() int {
	return 8 + 8 + 8 + 8 + 8 + 8 + 4 + len(r.name) + 4 + len(r.userName) + 4 + len(r.groupName)
}

type regularFileInfo struct {
	baseFileInfo
	size   int64
	chunks []string // FIXME: should be a [][]byte for efficiency
}

func (r *regularFileInfo) Record() (uint8, []byte) {
	writer := &bytes.Buffer{}
	writer.Write(r.baseFileInfo.Record())
	binary.Write(writer, binary.BigEndian, r.size)
	binary.Write(writer, binary.BigEndian, int32(len(r.chunks)))
	for _, chunk := range r.chunks {
		writer.Write([]byte(chunk))
	}
	return 3, writer.Bytes()
}

func (r *regularFileInfo) Len() int {
	return r.baseFileInfo.Len() + 8 + 4 + 96*len(r.chunks)
}

type fifoInfo struct {
	baseFileInfo
}

func (r *fifoInfo) Record() (uint8, []byte) {
	return 3, r.baseFileInfo.Record()
}

func (r *fifoInfo) Len() int {
	return r.baseFileInfo.Len()
}

type hardLinkInfo struct {
	name     string
	linkPath string
}

func (r *hardLinkInfo) Record() (uint8, []byte) {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, int32(len(r.name)))
	writer.Write([]byte(r.name))
	binary.Write(writer, binary.BigEndian, int32(len(r.linkPath)))
	writer.Write([]byte(r.linkPath))
	return 1, writer.Bytes()
}

func (r *hardLinkInfo) Len() int {
	return 4 + len(r.name) + 4 + len(r.name)
}

type symLinkInfo struct {
	baseFileInfo
	linkPath string
}

func (r *symLinkInfo) Record() (uint8, []byte) {
	writer := &bytes.Buffer{}
	writer.Write(r.baseFileInfo.Record())
	binary.Write(writer, binary.BigEndian, int32(len(r.linkPath)))
	writer.Write([]byte(r.linkPath))
	return 5, writer.Bytes()
}

func (r *symLinkInfo) Len() int {
	return r.baseFileInfo.Len() + 4 + len(r.linkPath)
}

type deviceInfo struct {
	baseFileInfo
	rdev uint64
}

func (r *deviceInfo) Record() []byte {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, r.rdev)
	return writer.Bytes()
}

func (r *deviceInfo) Len() int {
	return r.baseFileInfo.Len() + 8
}

type charDeviceInfo struct {
	deviceInfo
}

func (r *charDeviceInfo) Record() (uint8, []byte) {
	return 6, r.deviceInfo.Record()
}

type blockDeviceInfo struct {
	deviceInfo
}

func (r *blockDeviceInfo) Record() (uint8, []byte) {
	return 7, r.deviceInfo.Record()
}

type directoryInfo struct {
	baseFileInfo
	//contents []BaseFileInfo
}

func (r *directoryInfo) Record() (uint8, []byte) {
	return 2, r.baseFileInfo.Record()
}

func (r *directoryInfo) Len() int {
	return r.baseFileInfo.Len()
}

type endRecord struct {
	hash []byte
}

func (r *endRecord) Record() (uint8, []byte) {
	return 8, r.hash
}

func (r *endRecord) Len() int {
	return 48
}

func (b *BackupSet) fileRecordFromFileInfo(path string, info os.FileInfo) (record fileRecord, err error) {
	stat, statOk := info.Sys().(syscall.Stat_t)
	var inode devInode
	if statOk {
		inode := devInode{stat.Dev, stat.Ino}
		if path, ok := b.hardLinks[inode]; ok {
			return &hardLinkInfo{info.Name(), path}, nil
		}
	}
	mode := info.Mode()
	switch {
	case mode&os.ModeDir != 0:
		record = b.newDirectoryInfo(path, info)
	case mode&os.ModeSymlink != 0:
		path, err := os.Readlink(info.Name())
		if err != nil {
			return nil, err
		}
		record = &symLinkInfo{b.newBaseFileInfo(path, info), path}
	case mode&os.ModeDevice != 0:
		if statOk {
			if mode&os.ModeCharDevice != 0 {
				record = &charDeviceInfo{deviceInfo{b.newBaseFileInfo(path, info), stat.Rdev}}
			} else {
				record = &blockDeviceInfo{deviceInfo{b.newBaseFileInfo(path, info), stat.Rdev}}
			}
		} else {
			return nil, fmt.Errorf("Cannot handle device file " + info.Name())
		}
	case mode&os.ModeNamedPipe != 0:
		record = &fifoInfo{b.newBaseFileInfo(path, info)}
	case mode&os.ModeSocket != 0:
		return nil, fmt.Errorf("Cannot handle sockets")
	default:
		record, err = b.newRegularFileInfo(path, info)
		if err != nil {
			return nil, err
		}
	}
	if statOk {
		b.hardLinks[inode] = info.Name()
	}
	return record, nil
}

func (b *BackupSet) newDirectoryInfo(path string, info os.FileInfo) *directoryInfo {
	return &directoryInfo{b.newBaseFileInfo(path, info)}
}

func (b *BackupSet) newRegularFileInfo(path string, info os.FileInfo) (fileInfo *regularFileInfo, err error) {
	baseFileInfo := b.newBaseFileInfo(path, info)
	fileInfo = &regularFileInfo{baseFileInfo, info.Size(), make([]string, 0)}
	if info.Size() > 0 {
		storageHash := hmac.New(sha512.New384, b.secrets.chunkStorage)
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		chunk := make([]byte, 256*1024)
		plaintext := io.TeeReader(file, storageHash)
		var readErr error
		for {
			storageHash.Reset()
			var n int
			n, readErr = plaintext.Read(chunk)
			if n == 0 {
				if readErr != nil && readErr != io.EOF {
					return nil, err
				}
				break
			}
			storageLoc := storageHash.Sum(nil)
			hexStorageLoc := hex.EncodeToString(storageLoc)
			fileInfo.chunks = append(fileInfo.chunks, hexStorageLoc)
			// skip processing if we've seen this before
			if b.seenChunks[string(storageLoc)] {
				continue
			}
			chunkPath := filepath.Join(b.tempDir, hexStorageLoc)
			chunkFile, err := os.Create(chunkPath)
			if err != nil {
				return nil, err
			}
			defer chunkFile.Close()
			encryptor, err := newEncWriter(chunkFile, b.secrets)
			if err != nil {
				return nil, err
			}
			defer encryptor.Close()
			compressor := lzw.NewWriter(encryptor, lzw.LSB, 8)
			defer compressor.Close()
			_, err = compressor.Write(chunk[:n])
			if err != nil {
				return nil, err
			}
			b.seenChunks[string(storageLoc)] = true
			if readErr != nil {
				fmt.Println(readErr)
				break
			}
		}
		if readErr != io.EOF {
			return nil, err
		}
	}
	fmt.Println(">", info.Size(), fileInfo.chunks)
	return fileInfo, nil
}

func (b *BackupSet) newBaseFileInfo(path string, info os.FileInfo) baseFileInfo {
	stat := info.Sys()
	switch stat := stat.(type) {
	case *syscall.Stat_t:
		user, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
		var userName string
		if err != nil {
			userName = ""
		} else {
			userName = user.Username
		}
		aTime := time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
		cTime := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		mTime := time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec)
		return baseFileInfo{name: info.Name(),
			mode:     info.Mode(), //os.FileMode(stat.Mode),
			uid:      stat.Uid,
			gid:      stat.Gid,
			userName: userName,
			aTime:    aTime,
			cTime:    cTime,
			mTime:    mTime}
	default:
		return baseFileInfo{name: info.Name(),
			mode: info.Mode()}
	}
	panic("Can't get here")
}

// EnsureBackupSet will return the backup set tagged TAG, creating it
// if necessary
func EnsureBackupSet(backend Backend, secrets *Secrets, tag string) (b *BackupSet, err error) {
	digester := hmac.New(sha512.New384, secrets.metadataStorage)
	digester.Write([]byte(tag))
	id := hex.EncodeToString(digester.Sum(nil))
	fmt.Printf("id: %s", id)

	existingData, err := backend.ReadBackupSet(id)
	if err != nil {
		set, err := newBackupSet(tag, secrets)
		if err != nil {
			return nil, err
		}
		return set, nil
	}
	fmt.Printf("%d", len(existingData))
	return nil, fmt.Errorf("Unimplemented %s", tag)
}

func fileToName(file *os.File) (name string, err error) {
	info, err := file.Stat()
	if err != nil {
		return "*unknown file*", err
	}
	return info.Name(), nil
}

func (b *BackupSet) Encode() ([]byte, error) {
	digester := hmac.New(sha512.New384, b.secrets.metadataAuthentication)
	buffer := &bytes.Buffer{}
	writer := io.MultiWriter(digester, buffer)
	n, err := writer.Write([]byte{0}) // version
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("Error encoding backup set")
	}
	nonce, err := genKey(48)
	if err != nil {
		return nil, err
	}
	n, err = writer.Write(nonce)
	if err != nil {
		return nil, err
	}
	if n != len(nonce) {
		return nil, fmt.Errorf("Error encoding backup set")
	}
	keyMat := nistConcatKDF(b.secrets.metadataMaster, []byte("metadata encryption"), nonce, 48)
	key := keyMat[0:32]
	iv := keyMat[32:48]
	aesCypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	exitEarlyDigester := hmac.New(sha512.New384, b.secrets.metadataAuthentication)
	exitEarlyDigester.Write([]byte{0}) // version
	exitEarlyDigester.Write(nonce)
	exitEarlyDigester.Write(key)
	exitEarlyDigester.Write(iv)
	binary.Write(exitEarlyDigester, binary.BigEndian, int32(len(b.tag)))
	exitEarlyDigester.Write([]byte(b.tag))
	cypher := cipher.NewCTR(aesCypher, iv)
	stream := cipher.StreamWriter{S: cypher, W: buffer}
	writer = io.MultiWriter(digester, stream)
	binary.Write(writer, binary.BigEndian, int32(len(b.tag)))
	n, err = writer.Write([]byte(b.tag))
	if err != nil {
		return nil, err
	}
	if n != len([]byte(b.tag)) {
		return nil, fmt.Errorf("Error encoding backup set")
	}
	exitEarlySum := exitEarlyDigester.Sum(nil)
	n, err = writer.Write(exitEarlySum)
	if err != nil {
		return nil, err
	}
	if n != len(exitEarlySum) {
		return nil, fmt.Errorf("Error encoding backup set")
	}

	return buffer.Bytes(), nil
}
