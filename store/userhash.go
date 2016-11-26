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

package store

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	scryptauthFormatID string = "hmac_sha256_scrypt"
)

// fileExists returns whether the given file or directory exists or not
// this is from: stackoverflow.com/questions/10510691
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// readHashStr returns the contents of the user hash file seperated into format id
// string, change time and the whole hash string.
func readHashStr(filename string) (string, time.Time, string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", time.Unix(0, 0), "", err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	data, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", time.Unix(0, 0), "", err
	}

	parts := strings.SplitN(string(data), ":", 3)
	if len(parts) != 3 {
		return "", time.Unix(0, 0), "", fmt.Errorf("whawty.auth.store: hash file is invalid")
	}

	tmpTime, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Unix(0, 0), "", fmt.Errorf("whawty.auth.store: hash file is invalid, %v", err)
	}
	lastchange := time.Unix(tmpTime, 0)

	return parts[0], lastchange, parts[2], nil
}

func isFormatSupportedFull(filename string) (supported bool, formatID string, lastchange time.Time, params string, err error) {
	var hashStr string
	if formatID, lastchange, hashStr, err = readHashStr(filename); err != nil {
		return
	}

	switch formatID {
	case scryptauthFormatID:
		supported, params, err = scryptauthSupported(hashStr)
		return
	default:
		err = fmt.Errorf("whawty.auth.store: hash file format ID '%s' is not supported", formatID)
	}
	return
}

// IsFormatSupported checks if the format of the hash file is supported
func IsFormatSupported(filename string) error {
	supported, format, _, _, err := isFormatSupportedFull(filename)

	if err == nil && !supported {
		return fmt.Errorf("'%s' is not a supported format", format)
	}

	return err
}

// UserHash is the representation of a single user hash file inside the store.
// Use NewUserHash to create it.
type UserHash struct {
	store *Dir
	user  string
}

// NewUserHash creates a new whawty.auth UserHash for user inside BaseDir.
func NewUserHash(store *Dir, user string) (u *UserHash) {
	u = &UserHash{}
	u.store = store
	u.user = user
	return
}

func (u *UserHash) getFilename(isAdmin bool) string {
	filename := filepath.Join(u.store.BaseDir, u.user)
	if isAdmin {
		return filename + adminExt
	}
	return filename + userExt
}

func (u *UserHash) writeHashStr(password string, isAdmin bool, mayCreate bool) error {
	formatID := u.store.DefaultFormat

	var hashStr string
	switch formatID {
	case scryptauthFormatID:
		var err error
		hashStr, err = scryptauthGen(password, u.store)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("whawty.auth.store: default hash file fromat ID '%s' is not supported", formatID)
	}

	// Set the flags based on whether we expect to create the file
	// The file is opened read-only, since we write to a tmp file and atomically move it in place.
	flags := os.O_RDONLY | os.O_EXCL
	if mayCreate {
		flags = flags | os.O_CREATE
	}

	file, err := os.OpenFile(u.getFilename(isAdmin), flags, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	tmp, err := u.store.getTempFile()
	if err != nil {
		return err
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name()) // Ensure that the file gets removed in case of failure

	// Write the new password hash
	_, err = io.WriteString(tmp, fmt.Sprintf("%s:%d:%s\n", formatID, time.Now().Unix(), hashStr)) // TODO: retry if write was short??
	if err != nil {
		return err
	}

	// Create a reader for the original file
	reader := bufio.NewReader(file)

	// Skip the first line
	_, err = reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}

	// Write the rest of the old file to the new one
	_, err = reader.WriteTo(tmp)
	if err != nil {
		return err
	}

	// Atomically move the new file in place
	return os.Rename(tmp.Name(), file.Name())
}

// Add creates the hash file. It is an error if the user already exists.
func (u *UserHash) Add(password string, isAdmin bool) error {
	exists, _, err := u.Exists()
	if err != nil {
		return err
	} else if exists {
		return fmt.Errorf("whawty.auth.store: user '%s' already exists", u.user)
	}
	return u.writeHashStr(password, isAdmin, true)
}

// Update changes the password for user.
func (u *UserHash) Update(password string) error {
	exists, isAdmin, err := u.Exists()
	if err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}

	if err := IsFormatSupported(u.getFilename(isAdmin)); err != nil {
		return fmt.Errorf("whawty.auth.store: won't overwrite unsupported hash format", err)
	}

	return u.writeHashStr(password, isAdmin, false)
}

// SetAdmin changes the admin status of user.
func (u *UserHash) SetAdmin(adminState bool) error {
	exists, isAdmin, err := u.Exists()
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}
	if isAdmin == adminState {
		return nil
	}

	oldname := filepath.Join(u.store.BaseDir, u.user)
	newname := oldname
	if adminState {
		oldname += userExt
		newname += adminExt
	} else {
		oldname += adminExt
		newname += userExt
	}
	return os.Rename(oldname, newname)
}

// Remove deletes hash file.
func (u *UserHash) Remove() {
	filename := filepath.Join(u.store.BaseDir, u.user)
	os.Remove(filename + adminExt)
	os.Remove(filename + userExt)
	return
}

// Exists checks if user exists. It also returns whether user is an admin. This returns true even if
// the user's hash file format is not supported
func (u *UserHash) Exists() (exists bool, isAdmin bool, err error) {
	filename := filepath.Join(u.store.BaseDir, u.user)
	var ok bool
	if ok, err = fileExists(filename + adminExt); err != nil {
		return
	} else if ok {
		return true, true, nil
	}
	isAdmin = false
	exists, err = fileExists(filename + userExt)
	return
}

// Authenticate checks the user password. It also returns whether user is an admin, the password is upgradable
// and when the password was last changed.
func (u *UserHash) Authenticate(password string) (isAuthenticated, isAdmin, upgradeable bool, lastchange time.Time, err error) {
	var exists bool
	if exists, isAdmin, err = u.Exists(); err != nil {
		return
	} else if !exists {
		return false, false, false, time.Unix(0, 0), fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}

	var formatID, hashStr string
	if formatID, lastchange, hashStr, err = readHashStr(u.getFilename(isAdmin)); err != nil {
		return
	}

	switch formatID {
	case scryptauthFormatID:
		isAuthenticated, upgradeable, err = scryptauthCheck(password, hashStr, u.store)
		return
	default:
		err = fmt.Errorf("whawty.auth.store: hash file fromat ID '%s' is not supported", formatID)
	}
	if !upgradeable {
		upgradeable = (u.store.DefaultFormat != formatID)
	}

	isAuthenticated = false
	return
}
