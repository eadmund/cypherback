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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

func EnsureConfigDir() (path string, err error) {
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
