//
// Copyright (c) 2016 Christian Pointner <equinox@spreadspace.org>
//               2016 Markus Grüneis <gimpf@gimpf.org>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.auth nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// Package store implements a simple storage backend for whawty.auth password
// hash files. The schema of the whawty.auth password store can be found in the
// doc directory.
// If the environment contains the variable WHAWTY_AUTH_DEBUG logging will be enabled.
// By default whawty.auth doesn't log anything.
package store

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/spreadspace/scryptauth.v2"
)

var (
	wl         = log.New(ioutil.Discard, "[whawty.auth]\t", log.LstdFlags)
	userNameRe = regexp.MustCompile("^[-_.@A-Za-z0-9]+$")
)

const (
	adminExt string = ".admin"
	userExt  string = ".user"
)

func init() {
	if _, exists := os.LookupEnv("WHAWTY_AUTH_DEBUG"); exists {
		wl.SetOutput(os.Stderr)
	}
}

// Dir represents a directoy containing a whawty.auth password hash store. Use NewDir to create it.
type Dir struct {
	basedir      string
	Contexts     map[uint]*scryptauth.Context
	DefaultCtxID uint
}

// NewDir creates a new whawty.auth store using basedir as base directory.
func NewDir(basedir string) (d *Dir) {
	d = &Dir{}
	d.basedir = filepath.Clean(basedir)
	d.Contexts = make(map[uint]*scryptauth.Context)
	return
}

// NewDirFromConfig creates a new whawty.auth store from json config file.
func NewDirFromConfig(configfile string) (d *Dir, err error) {
	d = &Dir{}
	d.Contexts = make(map[uint]*scryptauth.Context)
	err = d.fromConfig(configfile)
	return
}

func openDir(path string) (*os.File, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	if i, err := dir.Stat(); err != nil {
		defer dir.Close()
		return nil, err
	} else {
		if !i.IsDir() {
			defer dir.Close()
			return nil, fmt.Errorf("Error: '%s' is not a directory", path)
		}
	}
	return dir, nil
}

func isDirEmpty(dir *os.File) bool {
	if _, err := dir.Readdir(1); err == nil {
		return false
	}
	return true
}

func checkUserFile(filename string) (valid bool, user string, isAdmin bool, err error) {
	switch filepath.Ext(filename) {
	case adminExt:
		user = strings.TrimSuffix(filename, adminExt)
		isAdmin = true
	case userExt:
		user = strings.TrimSuffix(filename, userExt)
	default:
		err = fmt.Errorf("file '%s' has invalid extension", filename)
		return
	}

	if userNameRe.MatchString(user) {
		valid = true
	}
	return
}

func hasSupportedAdminHashes(dir *os.File) (bool, error) {
	success := false
	for {
		last := false
		names, err := dir.Readdirnames(3)
		if err != nil {
			if err == io.EOF {
				last = true
			} else {
				return false, err
			}
		}

		for _, name := range names {
			valid, user, isAdmin, err := checkUserFile(name)
			if err != nil {
				return false, err
			}

			if !valid {
				wl.Printf("ignoring file for invalid username: '%s'", user)
			}
			if !isAdmin {
				continue
			}
			if exists, _ := fileExists(filepath.Join(dir.Name(), user) + userExt); exists {
				return false, fmt.Errorf("both '%s' and '%s' exist", name, user+userExt)
			}

			if ok, _ := IsFormatSupported(filepath.Join(dir.Name(), name)); ok {
				success = true
			}
		}

		if last {
			break
		}
	}
	return success, nil
}

func listSupportedUsers(dir *os.File, list UserList) error {
	for {
		last := false
		names, err := dir.Readdirnames(3)
		if err != nil {
			if err == io.EOF {
				last = true
			} else {
				return err
			}
		}

		for _, name := range names {
			valid, user, isAdmin, err := checkUserFile(name)
			if err != nil {
				return err
			}

			if !valid {
				wl.Printf("ignoring file for invalid username: '%s'", user)
				continue
			}

			if ok, _ := IsFormatSupported(filepath.Join(dir.Name(), name)); !ok {
				wl.Printf("ignoring file with unsupported hash format for username: '%s'", user)
				continue
			}

			list[user] = isAdmin
		}

		if last {
			break
		}
	}
	return nil
}

// Init initalizes the store by creating a password file for an admin user.
func (d *Dir) Init(admin, password string) error {
	dir, err := openDir(d.basedir)
	if err != nil {
		return err
	}
	defer dir.Close()

	if empty := isDirEmpty(dir); !empty {
		return fmt.Errorf("Error: '%s' is not empty", d.basedir)
	}
	return d.AddUser(admin, password, true)
}

// Check tests if the directory is a valid whawty.auth base directory.
func (d *Dir) Check() (ok bool, err error) {
	dir, err := openDir(d.basedir)
	if err != nil {
		return false, err
	}
	defer dir.Close()

	return hasSupportedAdminHashes(dir)
}

// AddUser adds user to the store. It is an error if the user already exists.
func (d *Dir) AddUser(user, password string, isAdmin bool) (err error) {
	if !userNameRe.MatchString(user) {
		return fmt.Errorf("username '%s' is invalid", user)
	}
	return NewUserHash(d, user).Add(password, isAdmin)
}

// UpdateUser changes the password of user. It is an error if the user does
// not exist.
func (d *Dir) UpdateUser(user, password string) (err error) {
	return NewUserHash(d, user).Update(password)
}

// SetAdmin changes the admin status of user. It is an error if the user does
// not exist.
func (d *Dir) SetAdmin(user string, adminState bool) (err error) {
	return NewUserHash(d, user).SetAdmin(adminState)
}

// RemoveUser removes user from the store.
func (d *Dir) RemoveUser(user string) {
	NewUserHash(d, user).Remove()
}

// UserList is the return value of List(). The key of the map is the username
// and the value is true if the user is an admin.
type UserList map[string]bool

// List returns a list of all users in the store.
func (d *Dir) List() (UserList, error) {
	dir, err := openDir(d.basedir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	list := make(UserList)
	err = listSupportedUsers(dir, list)
	return list, err
}

// Exists checks if user exists. It also returns whether user is an admin.
func (d *Dir) Exists(user string) (exists bool, isAdmin bool, err error) {
	return NewUserHash(d, user).Exists()
}

// Authenticate checks if user and password are a valid combination. It also returns
// whether user is an admin.
func (d *Dir) Authenticate(user, password string) (isAuthenticated, isAdmin bool, err error) {
	return NewUserHash(d, user).Authenticate(password)
}
