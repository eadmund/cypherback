package cypherback

import (
	//"fmt"
	"os"
	"testing"
)

func TestDirectoryInfo(t *testing.T) {
	backupset := BackupSet{}
	info, err := os.Lstat(".")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := backupset.fileRecordFromFileInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rec)
}
