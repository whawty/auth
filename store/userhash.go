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

type Hasher interface {
	GetFormatID() string
	IsValid(hashStr string) (bool, error)
	Generate(password string) (string, error)
	Check(password, hashStr string) (bool, error)
}

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

// readHashLine returns the first line of the user hash file including the trailing newline.
func readHashLine(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close() //nolint:errcheck

	line, err := bufio.NewReader(file).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return line, nil
}

// parseHashLine separates the first line of a user hash file into format id,
// change time, parameter id and the format specific hash string.
func parseHashLine(line string) (string, time.Time, uint, string, error) {
	parts := strings.SplitN(strings.TrimSuffix(line, "\n"), ":", 4)
	if len(parts) != 4 {
		return "", time.Unix(0, 0), 0, "", fmt.Errorf("whawty.auth.store: hash file is invalid")
	}

	tmpTime, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Unix(0, 0), 0, "", fmt.Errorf("whawty.auth.store: hash file is invalid, %v", err)
	}
	lastchange := time.Unix(tmpTime, 0)

	tmpParamID, err := strconv.ParseUint(parts[2], 10, 0)
	if err != nil {
		return "", time.Unix(0, 0), 0, "", fmt.Errorf("whawty.auth.store: hash file is invalid, %v", err)
	}
	paramID := uint(tmpParamID)

	return parts[0], lastchange, paramID, parts[3], nil
}

// readHashStr returns the contents of the user hash file separated into format id
// string, change time parameter id and the whole hash string.
func readHashStr(filename string) (string, time.Time, uint, string, error) {
	line, err := readHashLine(filename)
	if err != nil {
		return "", time.Unix(0, 0), 0, "", err
	}
	return parseHashLine(line)
}

func isFormatSupportedFull(filename string, store *Dir) (supported bool, formatID string, lastChange time.Time, paramID uint, err error) {
	var hashStr string
	if formatID, lastChange, paramID, hashStr, err = readHashStr(filename); err != nil {
		return
	}

	h := store.Params[paramID]
	if h == nil {
		err = fmt.Errorf("whawty.auth.store: parameter-set %d is unknown", paramID)
		return
	}
	if h.GetFormatID() != formatID {
		err = fmt.Errorf("whawty.auth.store: hash file format ID '%s' does not fit parameter-set %d", formatID, paramID)
		return
	}

	supported, err = h.IsValid(hashStr)
	return
}

func isFormatSupported(filename string, store *Dir) error {
	supported, format, _, _, err := isFormatSupportedFull(filename, store)

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

// generateHashLine creates a new first line for the user hash file using the
// default parameter-set.
func (u *UserHash) generateHashLine(password string) (string, error) {
	hasher := u.store.Params[u.store.Default]
	if hasher == nil {
		return "", fmt.Errorf("whawty.auth.store: no default parameter-set")
	}
	hashStr, err := hasher.Generate(password)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d:%d:%s\n", hasher.GetFormatID(), time.Now().Unix(), u.store.Default, hashStr), nil
}

// writeHashLine writes hashLine to a temporary file and moves it in place as filename.
// If create is false, everything after the first line of the existing file (the
// auxiliary data) is copied to the new file. If create is true, filename must not exist.
// The caller must hold the store lock.
func (u *UserHash) writeHashLine(filename, hashLine string, create bool) error {
	tmp, err := u.store.getTempFile()
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	defer tmp.Close()           //nolint:errcheck

	if _, err := io.WriteString(tmp, hashLine); err != nil {
		return err
	}

	if !create {
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck

		reader := bufio.NewReader(file)
		// Skip the first line and copy the rest of the old file to the new one
		if _, err := reader.ReadString('\n'); err != nil && err != io.EOF {
			return err
		}
		if _, err := reader.WriteTo(tmp); err != nil {
			return err
		}
	}

	// Flush the file's contents to disk
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if create {
		// Link fails if filename already exists, so we never overwrite a user
		// file and never leave an empty one behind.
		if err := os.Link(tmp.Name(), filename); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("whawty.auth.store: user '%s' already exists", u.user)
			}
			return err
		}
	} else {
		// Atomically move the new file in place
		if err := os.Rename(tmp.Name(), filename); err != nil {
			return err
		}
	}

	return syncDir(u.store.BaseDir)
}

// existsLocked is like Exists but also detects a user having both a .user and an .admin file.
func (u *UserHash) existsLocked() (exists bool, isAdmin bool, err error) {
	filename := filepath.Join(u.store.BaseDir, u.user)
	admin, err := fileExists(filename + adminExt)
	if err != nil {
		return false, false, err
	}
	user, err := fileExists(filename + userExt)
	if err != nil {
		return false, false, err
	}
	if admin && user {
		return true, true, fmt.Errorf("whawty.auth.store: both '%s' and '%s' exist", u.user+adminExt, u.user+userExt)
	}
	return admin || user, admin, nil
}

// Add creates the hash file. It is an error if the user already exists.
func (u *UserHash) Add(password string, isAdmin bool) error {
	hashLine, err := u.generateHashLine(password)
	if err != nil {
		return err
	}

	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	exists, _, err := u.existsLocked()
	if err != nil {
		return err
	} else if exists {
		return fmt.Errorf("whawty.auth.store: user '%s' already exists", u.user)
	}
	return u.writeHashLine(u.getFilename(isAdmin), hashLine, true)
}

// Update changes the password for user.
func (u *UserHash) Update(password string) error {
	hashLine, err := u.generateHashLine(password)
	if err != nil {
		return err
	}

	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	exists, isAdmin, err := u.existsLocked()
	if err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}

	if err := isFormatSupported(u.getFilename(isAdmin), u.store); err != nil {
		return fmt.Errorf("whawty.auth.store: won't overwrite unsupported hash format: %v", err)
	}

	return u.writeHashLine(u.getFilename(isAdmin), hashLine, false)
}

// SetAdmin changes the admin status of user.
func (u *UserHash) SetAdmin(adminState bool) error {
	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	exists, isAdmin, err := u.existsLocked()
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}
	if isAdmin == adminState {
		return nil
	}

	if err := os.Rename(u.getFilename(isAdmin), u.getFilename(adminState)); err != nil {
		return err
	}
	return syncDir(u.store.BaseDir)
}

// Remove deletes hash file. It is not an error if the user does not exist.
func (u *UserHash) Remove() error {
	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	for _, isAdmin := range []bool{true, false} {
		if err := os.Remove(u.getFilename(isAdmin)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return syncDir(u.store.BaseDir)
}

// Exists checks if user exists. It also returns whether user is an admin. This returns true even if
// the user's hash file format is not supported
func (u *UserHash) Exists() (exists bool, isAdmin bool, err error) {
	filename := filepath.Join(u.store.BaseDir, u.user)

	if ok, err := fileExists(filename + adminExt); err != nil {
		return false, false, err
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
	var paramID uint
	if formatID, lastchange, paramID, hashStr, err = readHashStr(u.getFilename(isAdmin)); err != nil {
		return
	}
	upgradeable = (u.store.Default != paramID)

	hasher := u.store.Params[paramID]
	if hasher == nil {
		return false, false, false, time.Unix(0, 0), fmt.Errorf("whawty.auth.store: parameter-set %d is unknown", paramID)
	}
	if hasher.GetFormatID() != formatID {
		return false, false, false, time.Unix(0, 0), fmt.Errorf("whawty.auth.store: hash file format ID '%s' does not fit parameter-set %d ", formatID, paramID)
	}

	isAuthenticated, err = hasher.Check(password, hashStr)
	return
}
