// A backup set is really just a metadata file; the chunks for its
// component files are stored separately.
package cypherback

import (
	"fmt"
	"os"
	"os/user"
	"time"
	"syscall"
)

type devInode struct {
	dev uint64
	inode uint64
}

type BackupSet struct {
	secrets *Secrets
	records []fileRecord
	hardLinks map[devInode]string
}

type fileRecord interface {
	
}

// FIXME: handle extended attributes

type baseFileInfo struct {
	name string
	mode os.FileMode
	userName string
	groupName string
	uid uint32
	gid uint32
	aTime time.Time
	mTime time.Time
	cTime time.Time
}

type regularFileInfo struct {
	baseFileInfo
	size int64
	//chunks []chunk
}

type fifoInfo struct {
	baseFileInfo
}

type hardLinkInfo struct {
	name string
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

func (b *BackupSet) fileRecordFromFileInfo(info os.FileInfo) (record fileRecord, err error) {
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
	case mode & os.ModeDir != 0:
		record = b.newDirectoryInfo(info)
	case mode & os.ModeSymlink != 0:
		path, err := os.Readlink(info.Name())
		if err != nil {
			return nil, err
		}
		record = symLinkInfo{b.newBaseFileInfo(info), path}
	case mode & os.ModeDevice != 0:
		if statOk {
			if mode & os.ModeCharDevice != 0 {
				record = charDeviceInfo{deviceInfo{b.newBaseFileInfo(info), stat.Rdev}}
			} else {
				record = blockDeviceInfo{deviceInfo{b.newBaseFileInfo(info), stat.Rdev}}
			}
		} else {
			return nil, fmt.Errorf("Cannot handle device file " + info.Name())
		}
	case mode & os.ModeNamedPipe != 0:
		record = fifoInfo{b.newBaseFileInfo(info)}
	case mode & os.ModeSocket != 0:
		return nil, fmt.Errorf("Cannot handle sockets")
	default:
		record, err = b.newRegularFileInfo(info)
		if err != nil {
			return nil, err
		}
	}
	if statOk {
		b.hardLinks[inode] = info.Name()
	}
	return record, nil
}

func (b *BackupSet) newDirectoryInfo(info os.FileInfo) directoryInfo {
	return directoryInfo{b.newBaseFileInfo(info)}
}

func (b *BackupSet) newRegularFileInfo(info os.FileInfo) (fileInfo regularFileInfo, err error) {
	// FIXME: chunk file here
	fileInfo = regularFileInfo{b.newBaseFileInfo(info), info.Size()}
	return fileInfo, nil
}

func (b *BackupSet) newBaseFileInfo(info os.FileInfo) (baseFileInfo) {
	stat := info.Sys()
	switch stat := stat.(type) {
	case syscall.Stat_t:
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
			mode: os.FileMode(stat.Mode),
			uid: stat.Uid,
			gid: stat.Gid,
			userName: userName,
			aTime: aTime,
			cTime: cTime,
			mTime: mTime}
	default:
		return baseFileInfo{name: info.Name(),
			mode: info.Mode()}
	}
	panic("Can't get here")
}