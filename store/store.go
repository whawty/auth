//
// Copyright (c) 2016 whawty contributors (see AUTHORS file)
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
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	wl                 = log.New(io.Discard, "[whawty.auth]\t", log.LstdFlags)
	userNameRe         = regexp.MustCompile("^[A-Za-z0-9][-_.@A-Za-z0-9]*$")
	errNoSupportedHash = errors.New("no admin with supported password hash found")
)

const (
	adminExt string = ".admin"
	userExt  string = ".user"
	tmpDir   string = ".tmp"
)

func init() {
	if _, exists := os.LookupEnv("WHAWTY_AUTH_DEBUG"); exists {
		wl.SetOutput(os.Stderr)
	}
}

// Dir represents a directory containing a whawty.auth password hash store. Use NewDir to create it.
type Dir struct {
	BaseDir string
	Default uint
	Params  map[uint]Hasher
}

// NewDir creates a new whawty.auth store using BaseDir as base directory.
func NewDir(BaseDir string) (d *Dir) {
	d = &Dir{}
	d.BaseDir = filepath.Clean(BaseDir)
	d.Default = 0
	d.Params = make(map[uint]Hasher)
	return
}

// NewDirFromConfig creates a new whawty.auth store from yaml config file.

func NewDirFromConfig(configfile string) (d *Dir, err error) {
	d = &Dir{}
	d.Params = make(map[uint]Hasher)
	err = d.fromConfig(configfile)
	return
}

func openDir(path string) (*os.File, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	i, err := dir.Stat()
	if err != nil {
		dir.Close() //nolint:errcheck
		return nil, err
	}
	if !i.IsDir() {
		dir.Close() //nolint:errcheck
		return nil, fmt.Errorf("'%s' is not a directory", path)
	}

	return dir, nil
}

// getTempFile provides a new, empty file in the base's .tmp directory,
// suitable for atomic file updates (by create/write/rename)
func (d *Dir) getTempFile() (tmp *os.File, err error) {
	tmpDir := filepath.Join(d.BaseDir, tmpDir)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return nil, err
	}

	return os.CreateTemp(tmpDir, "")
}

func isDirEmpty(dir *os.File) bool {
	entries, _ := dir.ReadDir(2)
	if len(entries) == 0 {
		return true
	}
	if len(entries) == 1 && entries[0].IsDir() && entries[0].Name() == ".tmp" {
		return true
	}
	return false
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

// Init initializes the store by creating a password file for an admin user.
func (d *Dir) Init(admin, password string) error {
	dir, err := openDir(d.BaseDir)
	if err != nil {
		return err
	}
	defer dir.Close() //nolint:errcheck

	if empty := isDirEmpty(dir); !empty {
		return fmt.Errorf("'%s' is not empty", d.BaseDir)
	}
	return d.AddUser(admin, password, true)
}

// Check tests if the directory is a valid whawty.auth base directory.
func (d *Dir) Check() error {
	dir, err := openDir(d.BaseDir)
	if err != nil {
		return err
	}
	defer dir.Close() //nolint:errcheck
	names, err := dir.Readdirnames(0)
	if err != nil && err != io.EOF {
		return err
	}

	result := errNoSupportedHash
	for _, name := range names {
		// Skip the '.tmp' directory
		if name == tmpDir {
			continue
		}

		valid, user, isAdmin, err := checkUserFile(name)
		if err != nil {
			return err
		}

		if !valid {
			wl.Printf("ignoring file for invalid username: '%s'", user)
		}

		if isAdmin {
			if exists, _ := fileExists(filepath.Join(dir.Name(), user) + userExt); exists {
				return fmt.Errorf("both '%s' and '%s' exist", name, user+userExt)
			}
		} else {
			if exists, _ := fileExists(filepath.Join(dir.Name(), user) + adminExt); exists {
				return fmt.Errorf("both '%s' and '%s' exist", name, user+adminExt)
			}
			continue
		}

		if isFormatSupported(filepath.Join(dir.Name(), name), d) == nil {
			result = nil
		}
	}

	return result
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

// User holds basic information about a specific user. This is used as the
// value type for UserList.
type User struct {
	IsAdmin     bool      `json:"admin"`
	LastChanged time.Time `json:"lastchanged"`
}

// UserList is the return value of List(). The key of the map is the username.
type UserList map[string]User

// List returns a list of all supported users in the store.
func (d *Dir) List() (UserList, error) {
	dir, err := openDir(d.BaseDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close() //nolint:errcheck

	list := make(UserList)
	for {
		last := false
		names, err := dir.Readdirnames(3)
		if err != nil {
			if err == io.EOF {
				last = true
			} else {
				return list, err
			}
		}

		for _, name := range names {
			// Skip the '.tmp' directory
			if name == tmpDir {
				continue
			}

			valid, user, isAdmin, err := checkUserFile(name)
			if err != nil {
				return list, err
			}

			if !valid {
				wl.Printf("ignoring file for invalid username: '%s'", user)
				continue
			}

			ok, _, lastchanged, _, _ := isFormatSupportedFull(filepath.Join(dir.Name(), name), d)
			if !ok {
				wl.Printf("ignoring file with unsupported hash format for username: '%s'", user)
				continue
			}

			list[user] = User{isAdmin, lastchanged}
		}

		if last {
			break
		}
	}
	return list, err
}

// UserFull holds additional information about a specific user. This is used as the
// value type for UserListFull.
type UserFull struct {
	IsAdmin     bool      `json:"admin"`
	LastChanged time.Time `json:"lastchanged"`
	IsValid     bool      `json:"valid"`
	IsSupported bool      `json:"supported"`
	FormatID    string    `json:"formatid"`
	ParamID     uint      `json:"paramid"`
}

// UserListFull is the return value of ListFull(). The key of the map is the username.
type UserListFull map[string]UserFull

// ListFull returns a list of all users in the store. This includes users with
// unsupported hash formats.
func (d *Dir) ListFull() (UserListFull, error) {
	dir, err := openDir(d.BaseDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close() //nolint:errcheck

	list := make(UserListFull)
	for {
		last := false
		names, err := dir.Readdirnames(3)
		if err != nil {
			if err == io.EOF {
				last = true
			} else {
				return list, err
			}
		}

		for _, name := range names {
			// Skip the '.tmp' directory
			if name == tmpDir {
				continue
			}

			var user UserFull
			var err error
			var username string
			if user.IsValid, username, user.IsAdmin, err = checkUserFile(name); err != nil {
				return list, err
			}
			user.IsSupported, user.FormatID, user.LastChanged, user.ParamID, _ = isFormatSupportedFull(filepath.Join(dir.Name(), name), d)
			list[username] = user
		}

		if last {
			break
		}
	}
	return list, err
}

// Exists checks if user exists. It also returns whether user is an admin.
func (d *Dir) Exists(user string) (exists bool, isAdmin bool, err error) {
	return NewUserHash(d, user).Exists()
}

// Authenticate checks if user and password are a valid combination. It also returns
// whether user is an admin, the password is upgradeable and when the password was last changed.
func (d *Dir) Authenticate(user, password string) (isAuthenticated, isAdmin, upgradeable bool, lastchange time.Time, err error) {
	return NewUserHash(d, user).Authenticate(password)
}
