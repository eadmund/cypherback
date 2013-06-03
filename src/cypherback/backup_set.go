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
	"math"
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
	tag            string
	secrets        *Secrets
	records        []fileRecord
	hardLinks      map[devInode]string
	seenChunks     map[string]bool
	tempDir        string
	lastStartIndex int
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
	date   time.Time
	length uint32
}

func readStartRecord(reader io.Reader) (fileRecord, error) {
	var seconds int64
	var length uint32
	err := binary.Read(reader, binary.BigEndian, &seconds)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	return startRecord{date: time.Unix(seconds, 0), length: length}, nil
}

func (r startRecord) Record() (recordType uint8, data []byte) {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, r.date.Unix())
	binary.Write(writer, binary.BigEndian, r.length)
	return 0, writer.Bytes()
}

func (r startRecord) Len() uint32 {
	return 8 + 4
}

type fileRecord interface {
	Record() (recordType uint8, data []byte)
	Len() uint32
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

func (r baseFileInfo) Record() []byte {
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

func readBaseFileInfo(reader io.Reader) (b baseFileInfo, err error) {
	var mode, uid, gid, atime, mtime, ctime int64
	var nameLen, userNameLen, groupNameLen uint32
	err = binary.Read(reader, binary.BigEndian, &mode)
	if err != nil {
		return b, err
	}
	b.mode = os.FileMode(mode)
	err = binary.Read(reader, binary.BigEndian, &uid)
	if err != nil {
		return b, err
	}
	b.uid = uint32(uid)
	err = binary.Read(reader, binary.BigEndian, &gid)
	if err != nil {
		return b, err
	}
	b.gid = uint32(gid)
	err = binary.Read(reader, binary.BigEndian, &atime)
	if err != nil {
		return b, err
	}
	b.aTime = time.Unix(0, atime)
	err = binary.Read(reader, binary.BigEndian, &mtime)
	if err != nil {
		return b, err
	}
	b.mTime = time.Unix(0, mtime)
	err = binary.Read(reader, binary.BigEndian, &ctime)
	if err != nil {
		return b, err
	}
	b.cTime = time.Unix(0, ctime)
	err = binary.Read(reader, binary.BigEndian, &nameLen)
	if err != nil {
		return b, err
	}
	b.name, err = readLenString(reader, nameLen)
	if err != nil {
		return b, err
	}
	err = binary.Read(reader, binary.BigEndian, &userNameLen)
	if err != nil {
		return b, err
	}
	b.userName, err = readLenString(reader, userNameLen)
	if err != nil {
		return b, err
	}
	err = binary.Read(reader, binary.BigEndian, &groupNameLen)
	if err != nil {
		return b, err
	}
	b.groupName, err = readLenString(reader, groupNameLen)
	return b, err
}

// FIXME: need to check for _each_ Len that it does not exceed math.MaxUint32

func (r baseFileInfo) Len() uint32 {
	if len(r.name) > math.MaxUint32 {
		panic(fmt.Errorf("Record name length > %d", math.MaxUint32))
	}
	if len(r.userName) > math.MaxUint32 {
		panic(fmt.Errorf("Record username length > %d", math.MaxUint32))
	}
	if len(r.groupName) > math.MaxUint32 {
		panic(fmt.Errorf("Record groupname length > %d", math.MaxUint32))
	}
	return 8 + 8 + 8 + 8 + 8 + 8 + 4 + uint32(len(r.name)) + 4 + uint32(len(r.userName)) + 4 + uint32(len(r.groupName))
}

type regularFileInfo struct {
	baseFileInfo
	size   int64
	chunks []string // FIXME: should be a [][]byte for efficiency
}

func readRegularFile(reader io.Reader) (fileRecord, error) {
	baseInfo, err := readBaseFileInfo(reader)
	if err != nil {
		return nil, err
	}
	r := regularFileInfo{baseInfo, 0, nil}
	err = binary.Read(reader, binary.BigEndian, &r.size)
	if err != nil {
		return nil, err
	}
	var numChunks uint32
	err = binary.Read(reader, binary.BigEndian, &numChunks)
	for i := 0; i < int(numChunks); i++ {
		chunk, err := readLenString(reader, 96)
		if err != nil {
			return nil, err
		}
		r.chunks = append(r.chunks, chunk)
	}
	return r, nil
}

func (r regularFileInfo) Record() (uint8, []byte) {
	writer := &bytes.Buffer{}
	writer.Write(r.baseFileInfo.Record())
	binary.Write(writer, binary.BigEndian, r.size)
	binary.Write(writer, binary.BigEndian, uint32(len(r.chunks)))
	for _, chunk := range r.chunks {
		writer.Write([]byte(chunk))
	}
	return 3, writer.Bytes()
}

func (r regularFileInfo) Len() uint32 {
	// FIXME: is this a practical max number of chunks?
	if 96*len(r.chunks) > math.MaxUint32 {
		panic(fmt.Errorf("Chunk length * 96 > %d", math.MaxUint32))
	}
	return uint32(r.baseFileInfo.Len()) + 8 + 4 + uint32(96*len(r.chunks))
}

type fifoInfo struct {
	baseFileInfo
}

func (r fifoInfo) Record() (uint8, []byte) {
	return 3, r.baseFileInfo.Record()
}

func (r fifoInfo) Len() uint32 {
	return r.baseFileInfo.Len()
}

type hardLinkInfo struct {
	name     string
	linkPath string
}

func readHardLink(reader io.Reader) (fileRecord, error) {
	var pathLength uint32
	var path string
	var targetPathLength uint32
	var targetPath string
	err := binary.Read(reader, binary.BigEndian, &pathLength)
	if err != nil {
		return nil, err
	}
	pathBytes := make([]byte, pathLength)
	n, err := reader.Read(pathBytes)
	if err != nil {
		return nil, err
	}
	if uint32(n) != pathLength {
		return nil, fmt.Errorf("Error decoding backup set")
	}
	err = binary.Read(reader, binary.BigEndian, &targetPathLength)
	if err != nil {
		return nil, err
	}
	targetPathBytes := make([]byte, targetPathLength)
	n, err = reader.Read(targetPathBytes)
	if err != nil {
		return nil, err
	}
	if uint32(n) != targetPathLength {
		return nil, fmt.Errorf("Error decoding backup set")
	}
	return hardLinkInfo{name: path, linkPath: targetPath}, nil
}

func (r hardLinkInfo) Record() (uint8, []byte) {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, int32(len(r.name)))
	writer.Write([]byte(r.name))
	binary.Write(writer, binary.BigEndian, int32(len(r.linkPath)))
	writer.Write([]byte(r.linkPath))
	return 1, writer.Bytes()
}

func (r hardLinkInfo) Len() uint32 {
	if len(r.name) > math.MaxUint32 {
		panic(fmt.Errorf("Record name length > %d", math.MaxUint32))
	}
	if len(r.linkPath) > math.MaxUint32 {
		panic(fmt.Errorf("Record link path > %d", math.MaxUint32))
	}
	return 4 + uint32(len(r.name)) + 4 + uint32(len(r.linkPath))
}

type symLinkInfo struct {
	baseFileInfo
	linkPath string
}

func (r symLinkInfo) Record() (uint8, []byte) {
	writer := &bytes.Buffer{}
	writer.Write(r.baseFileInfo.Record())
	binary.Write(writer, binary.BigEndian, int32(len(r.linkPath)))
	writer.Write([]byte(r.linkPath))
	return 5, writer.Bytes()
}

func (r symLinkInfo) Len() uint32 {
	if len(r.linkPath) > math.MaxUint32 {
		panic(fmt.Errorf("Link path > %d", math.MaxUint32))
	}
	return r.baseFileInfo.Len() + 4 + uint32(len(r.linkPath))
}

type deviceInfo struct {
	baseFileInfo
	rdev uint64
}

func (r deviceInfo) Record() []byte {
	writer := &bytes.Buffer{}
	binary.Write(writer, binary.BigEndian, r.rdev)
	return writer.Bytes()
}

func (r deviceInfo) Len() uint32 {
	return r.baseFileInfo.Len() + 8
}

type charDeviceInfo struct {
	deviceInfo
}

func (r charDeviceInfo) Record() (uint8, []byte) {
	return 6, r.deviceInfo.Record()
}

type blockDeviceInfo struct {
	deviceInfo
}

func (r blockDeviceInfo) Record() (uint8, []byte) {
	return 7, r.deviceInfo.Record()
}

type directoryInfo struct {
	baseFileInfo
	//contents []BaseFileInfo
}

func readDirectory(reader io.Reader) (fileRecord, error) {
	base, err := readBaseFileInfo(reader)
	return directoryInfo{base}, err
}

func (r directoryInfo) Record() (uint8, []byte) {
	return 2, r.baseFileInfo.Record()
}

func (r directoryInfo) Len() uint32 {
	return r.baseFileInfo.Len()
}

type endRecord struct {
	hash []byte
}

func readEndRecord(reader io.Reader) (fileRecord, error) {
	hash := make([]byte, 48)
	_, err := io.ReadFull(reader, hash)
	if err != nil {
		return nil, err
	}
	return endRecord{hash}, nil
}

func (r endRecord) Record() (uint8, []byte) {
	return 8, r.hash
}

func (r endRecord) Len() uint32 {
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
	//fmt.Println(">", info.Size(), fileInfo.chunks)
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

func tagToId(secrets *Secrets, tag string) string {
	digester := hmac.New(sha512.New384, secrets.metadataStorage)
	digester.Write([]byte(tag))
	return hex.EncodeToString(digester.Sum(nil))
}

// EnsureBackupSet will return the backup set tagged TAG, creating it
// if necessary
func EnsureBackupSet(backend Backend, secrets *Secrets, tag string) (b *BackupSet, err error) {
	id := tagToId(secrets, tag)
	existingData, err := backend.ReadBackupSet(secrets.HexId(), id)
	if err != nil {
		set, err := newBackupSet(tag, secrets)
		if err != nil {
			return nil, err
		}
		return set, nil
	}
	return decodeBackupSet(secrets, existingData)
}

func fileToName(file *os.File) (name string, err error) {
	info, err := file.Stat()
	if err != nil {
		return "*unknown file*", err
	}
	return info.Name(), nil
}

func (b *BackupSet) encode() ([]byte, error) {
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
	err = binary.Write(exitEarlyDigester, binary.BigEndian, uint32(len(b.tag)))
	if err != nil {
		return nil, err
	}
	exitEarlyDigester.Write([]byte(b.tag))
	cypher := cipher.NewCTR(aesCypher, iv)
	writer = cipher.StreamWriter{S: cypher, W: writer}
	//writer = io.MultiWriter(digester, stream)
	err = binary.Write(writer, binary.BigEndian, uint32(len(b.tag)))
	if err != nil {
		return nil, err
	}
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
	for _, record := range b.records {
		recordType, data := record.Record()
		binary.Write(writer, binary.BigEndian, uint8(0))
		binary.Write(writer, binary.BigEndian, recordType)
		n, err = writer.Write(data)
		if err != nil {
			return nil, err
		}
		if n != len(data) {
			return nil, fmt.Errorf("Error encoding backup set")
		}
	}
	n, err = buffer.Write(digester.Sum(nil))
	if err != nil {
		return nil, err
	}
	if n != 48 {
		return nil, fmt.Errorf("Error encoding backup set")
	}
	return buffer.Bytes(), nil
}

func decodeBackupSet(secrets *Secrets, data []byte) (*BackupSet, error) {
	b, err := newBackupSet("", secrets)
	if err != nil {
		return nil, err
	}
	digester := hmac.New(sha512.New384, secrets.metadataAuthentication)
	buffer := bytes.NewReader(data)
	reader := io.TeeReader(buffer, digester)
	version := make([]byte, 1)
	n, err := reader.Read(version)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("Error reading backup set version")
	}
	if version[0] != 0 {
		return nil, fmt.Errorf("Unsupported file version %d", version[0])
	}
	nonce := make([]byte, 48)
	n, err = reader.Read(nonce)
	if err != nil {
		return nil, err
	}
	if n != 48 {
		return nil, fmt.Errorf("Error reading backup set nonce")
	}
	keyMat := nistConcatKDF(secrets.metadataMaster, []byte("metadata encryption"), nonce, 48)
	key := keyMat[0:32]
	iv := keyMat[32:48]
	aesCypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	exitEarlyDigester := hmac.New(sha512.New384, secrets.metadataAuthentication)
	exitEarlyDigester.Write([]byte{0}) // version
	exitEarlyDigester.Write(nonce)
	exitEarlyDigester.Write(key)
	exitEarlyDigester.Write(iv)
	cypher := cipher.NewCTR(aesCypher, iv)
	reader = cipher.StreamReader{S: cypher, R: reader}
	//reader = io.TeeReader(stream, digester)
	var tagLen uint32
	err = binary.Read(reader, binary.BigEndian, &tagLen)
	if err != nil {
		return nil, err
	}
	err = binary.Write(exitEarlyDigester, binary.BigEndian, tagLen)
	if err != nil {
		return nil, err
	}
	tagBytes := make([]byte, tagLen)
	n, err = reader.Read(tagBytes)
	if err != nil {
		return nil, err
	}
	if n != int(tagLen) {
		return nil, fmt.Errorf("Error decoding backup set")
	}
	exitEarlyDigester.Write(tagBytes)
	b.tag = string(tagBytes)
	exitEarlySum := make([]byte, 48)
	n, err = reader.Read(exitEarlySum)
	if err != nil {
		return nil, err
	}
	if n != len(exitEarlySum) {
		return nil, fmt.Errorf("Error decoding backup set")
	}
	if !bytes.Equal(exitEarlySum, exitEarlyDigester.Sum(nil)) {
		return nil, fmt.Errorf("Error decoding backup set")
	}
	var bytesToRead uint32
	for {
		var record fileRecord
		var version uint8
		var recordType uint8
		err = binary.Read(reader, binary.BigEndian, &version)
		if err != nil {
			return nil, err
		}
		if version != 0 {
			return nil, fmt.Errorf("Error decoding backup set: unknown version %d", version)
		}
		err = binary.Read(reader, binary.BigEndian, &recordType)
		if err != nil {
			return nil, err
		}
		switch recordType {
		case 0:
			if bytesToRead != 0 {
				return nil, fmt.Errorf("Error decoding backup set: unexpected start record")
			}
			record, err = readStartRecord(reader)
			bytesToRead = record.Len() + record.(startRecord).length
		case 1:
			record, err = readHardLink(reader)
		case 2:
			record, err = readDirectory(reader)
		case 3:
			record, err = readRegularFile(reader)
		case 8:
			record, err = readEndRecord(reader)
		default:
			return nil, fmt.Errorf("Error decoding backup set: unsupported type %d", recordType)
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
		b.records = append(b.records, record)
		bytesToRead -= record.Len()
		if bytesToRead == 0 {
			break
		}
	}
	digest, err := ioutil.ReadAll(buffer)
	/*digest := make([]byte, 48)
	n, err = buffer.Read(digest)*/
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(digest) != 48 {
		return nil, fmt.Errorf("Error decoding backup set: could not read authentication tag %d", len(digest))
	}
	if !bytes.Equal(digest, digester.Sum(nil)) {
		return nil, fmt.Errorf("Error decoding backup set: invalid authentication tag %s/%s", hex.EncodeToString(digest), hex.EncodeToString(digester.Sum(nil)))
	}
	return b, nil
}

func (b *BackupSet) StartBackup() error {
	if b.records != nil {
		_, ok := b.records[len(b.records)-1].(endRecord)
		if !ok {
			return fmt.Errorf("Final existing record in backup set is not an end record")
		}
	}
	// will update the start record when ending backup
	start := startRecord{date: time.Now()}
	b.records = append(b.records, start)
	b.lastStartIndex = len(b.records) - 1
	return nil
}

func (b *BackupSet) EndBackup() error {
	if b.records == nil {
		return fmt.Errorf("Cannot end unstarted backup run")
	}
	start, ok := b.records[b.lastStartIndex].(startRecord)
	if !ok {
		return fmt.Errorf("Corrupted backup set: purported last start record is not a start record")
	}
	start.length = 0
	digester := sha512.New384()
	for i := b.lastStartIndex + 1; i < len(b.records); i++ {
		start.length += b.records[i].Len()
		recordType, data := b.records[i].Record()
		err := binary.Write(digester, binary.BigEndian, uint8(0))
		if err != nil {
			return err
		}
		err = binary.Write(digester, binary.BigEndian, recordType)
		if err != nil {
			return err
		}
		digester.Write(data)
	}
	end := endRecord{digester.Sum(nil)}
	start.length += end.Len()
	b.records[b.lastStartIndex] = start
	b.records = append(b.records, end)
	return nil
}

func (b *BackupSet) Write(backend Backend) error {
	encSet, err := b.encode()
	if err != nil {
		return err
	}
	secretsId := b.secrets.HexId()
	chunkInfo, err := ioutil.ReadDir(b.tempDir)
	if err != nil {
		return err
	}
	for i := range chunkInfo {
		path := filepath.Join(b.tempDir, chunkInfo[i].Name())
		chunkFile, err := os.Open(path)
		if err != nil {
			return err
		}
		chunk, err := ioutil.ReadAll(chunkFile)
		if err != nil {
			return err
		}
		err = backend.WriteChunk(secretsId, filepath.Base(path), chunk)
		if err != nil {
			return err
		}
	}

	return backend.WriteBackupSet(secretsId, tagToId(b.secrets, b.tag), encSet)
}

func readLenString(reader io.Reader, length uint32) (string, error) {
	stringBytes := make([]byte, length)
	_, err := io.ReadFull(reader, stringBytes)
	return string(stringBytes), err
}
