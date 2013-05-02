package cypherback

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

func ensureConfigDir() (path string, err error) {
	usr, err := user.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return "", err
	}
	homedir, err := filepath.EvalSymlinks(usr.HomeDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return "", err
	}
	configdir := filepath.Join(homedir, ".cypherback")
	info, err := os.Stat(configdir)
	if err != nil {
		switch err := err.(type) {
		case *os.PathError:
			// try to create it
			if os.Mkdir(configdir, 0700) != nil {
				fmt.Fprintln(os.Stderr, err.Err)
			}
			return configdir, nil
		default:
			fmt.Fprintln(os.Stderr, err)
		}
		return "", err
	}
	if info.Mode()&0077 != 0 {
		return "", fmt.Errorf("Bad permissions on ~/.cypherback")
	}
	return configdir, nil
}
