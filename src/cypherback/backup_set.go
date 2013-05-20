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
	"compress/lzw"
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
	secrets    *Secrets
	records    []fileRecord
	hardLinks  map[devInode]string
	seenChunks map[string]bool
	tempDir    string
}

func newBackupSet(secrets *Secrets) (backupSet *BackupSet, err error) {
	backupSet = &BackupSet{secrets: secrets}
	backupSet.hardLinks = make(map[devInode]string)
	backupSet.seenChunks = make(map[string]bool)
	backupSet.tempDir, err = ioutil.TempDir("/tmp/", "cypherback")
	if err != nil {
		return nil, err
	}
	return backupSet, nil
}

type fileRecord interface {
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

type regularFileInfo struct {
	baseFileInfo
	size   int64
	chunks []string
}

type fifoInfo struct {
	baseFileInfo
}

type hardLinkInfo struct {
	name     string
	linkPath string
}

type symLinkInfo struct {
	baseFileInfo
	linkPath string
}

type deviceInfo struct {
	baseFileInfo
	rdev uint64
}

type charDeviceInfo struct {
	deviceInfo
}

type blockDeviceInfo struct {
	deviceInfo
}

type directoryInfo struct {
	baseFileInfo
	//contents []BaseFileInfo
}

func (b *BackupSet) fileRecordFromFileInfo(path string, info os.FileInfo) (record fileRecord, err error) {
	stat, statOk := info.Sys().(syscall.Stat_t)
	var inode devInode
	if statOk {
		inode := devInode{stat.Dev, stat.Ino}
		if path, ok := b.hardLinks[inode]; ok {
			return hardLinkInfo{info.Name(), path}, nil
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
		record = symLinkInfo{b.newBaseFileInfo(path, info), path}
	case mode&os.ModeDevice != 0:
		if statOk {
			if mode&os.ModeCharDevice != 0 {
				record = charDeviceInfo{deviceInfo{b.newBaseFileInfo(path, info), stat.Rdev}}
			} else {
				record = blockDeviceInfo{deviceInfo{b.newBaseFileInfo(path, info), stat.Rdev}}
			}
		} else {
			return nil, fmt.Errorf("Cannot handle device file " + info.Name())
		}
	case mode&os.ModeNamedPipe != 0:
		record = fifoInfo{b.newBaseFileInfo(path, info)}
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

func (b *BackupSet) newDirectoryInfo(path string, info os.FileInfo) directoryInfo {
	return directoryInfo{b.newBaseFileInfo(path, info)}
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
			// skip processing if we've seen this before
			if b.seenChunks[string(storageLoc)] {
				continue
			}
			hexStorageLoc := hex.EncodeToString(storageLoc)
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
			fileInfo.chunks = append(fileInfo.chunks, hexStorageLoc)
			b.seenChunks[string(storageLoc)] = true
			if readErr != nil {
				break
			}
		}
		if readErr != io.EOF {
			return nil, err
		}
	}
	fmt.Println(info.Size(), fileInfo.chunks)
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

// EnsureSet will return the backup set named NAME, creating it if necessary
func EnsureSet(secrets *Secrets, name string) (b *BackupSet, err error) {
	return nil, fmt.Errorf("Unimplemented %s", name)
}

func fileToName(file *os.File) (name string, err error) {
	info, err := file.Stat()
	if err != nil {
		return "*unknown file*", err
	}
	return info.Name(), nil
}

func ReadTag(file *os.File) (tag string, err error) {
	name, _ := fileToName(file)

	version := make([]byte, 1)
	n, err := file.Read(version)
	// checking before processing because file must always have more
	// than just a version, so EOF is an error here
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", fmt.Errorf("Couldn't read version from backup set %s", name)
	}
	if len(version) != 1 || version[0] != 0 {
		return "", fmt.Errorf("Unknown file version %d in %s", version, name)
	}
	// FIXME: decrypt; it's not in plaintext
	tagLenBytes := make([]byte, 4)
	n, err = file.Read(tagLenBytes)
	if n != 4 {
		return "", fmt.Errorf("Couldn't read tag length from %s", name)
	}
	var tagLen int32
	err = binary.Read(file, binary.BigEndian, tagLen)
	if err != nil {
		return "", err
	}
	tagBytes := make([]byte, tagLen)
	n, err = file.Read(tagBytes)
	if n != int(tagLen) {
		return "", fmt.Errorf("Couldn't read entire tag from %s", name)
	}
	if err != io.EOF && err != nil {
		return "", err
	}
	return string(tagBytes), nil
}
