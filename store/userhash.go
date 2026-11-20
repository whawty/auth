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
	"errors"
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
	return readHashLineFrom(file)
}

// readHashLineFrom returns the first line of an open user hash file including the
// trailing newline.
func readHashLineFrom(file *os.File) (string, error) {
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
	line, err := readHashLine(filename)
	if err != nil {
		return false, "", time.Unix(0, 0), 0, err
	}
	return isLineSupportedFull(line, store)
}

func isLineSupportedFull(line string, store *Dir) (supported bool, formatID string, lastChange time.Time, paramID uint, err error) {
	var hashStr string
	if formatID, lastChange, paramID, hashStr, err = parseHashLine(line); err != nil {
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

// isValidName returns whether the user name is valid. User names come from clients and become
// part of paths, so a name like '../x' would read and write files outside of the store.
func (u *UserHash) isValidName() bool {
	return userNameRe.MatchString(u.user)
}

func (u *UserHash) getFilename(isAdmin bool) string {
	filename := filepath.Join(u.store.BaseDir, u.user)
	if isAdmin {
		return filename + adminExt
	}
	return filename + userExt
}

// generateHashLine creates a new first line for the user hash file using the
// default parameter-set. lastChange is the time the password has been changed.
func (u *UserHash) generateHashLine(password string, lastChange time.Time) (string, error) {
	hasher := u.store.Params[u.store.Default]
	if hasher == nil {
		return "", fmt.Errorf("whawty.auth.store: no default parameter-set")
	}
	hashStr, err := hasher.Generate(password)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d:%d:%s\n", hasher.GetFormatID(), lastChange.Unix(), u.store.Default, hashStr), nil
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
	if !u.isValidName() {
		return fmt.Errorf("whawty.auth.store: username '%s' is invalid", u.user)
	}
	hashLine, err := u.generateHashLine(password, time.Now())
	if err != nil {
		return err
	}

	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if format, _, err := u.locateLocked(); err != nil {
		return err
	} else if format != formatNone {
		return fmt.Errorf("whawty.auth.store: user '%s' already exists", u.user)
	}
	// Until the store has been migrated, new users are added in format v1 as well.
	if hasV1Users, err := u.store.hasV1Users(); err != nil {
		return err
	} else if hasV1Users {
		return u.writeHashLine(u.getFilename(isAdmin), hashLine, true)
	}
	return u.addUserDir(hashLine, isAdmin)
}

// Update changes the password for user.
func (u *UserHash) Update(password string) error {
	if !u.isValidName() {
		return fmt.Errorf("whawty.auth.store: username '%s' is invalid", u.user)
	}
	hashLine, err := u.generateHashLine(password, time.Now())
	if err != nil {
		return err
	}

	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	format, isAdmin, err := u.locateLocked()
	if err != nil {
		return err
	} else if format == formatNone {
		return fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}

	path := u.hashPath(format, isAdmin)
	if err := isFormatSupported(path, u.store); err != nil {
		return fmt.Errorf("whawty.auth.store: won't overwrite unsupported hash format: %v", err)
	}
	if format == formatV2 {
		return u.store.replaceFile(path, hashLine)
	}
	return u.writeHashLine(path, hashLine, false)
}

// Upgrade re-hashes password using the default parameter-set. This only happens if the
// user's hash uses a different parameter-set, password is still the user's current
// password and the hash hasn't been changed by somebody else in the meantime. The time
// of the last password change is kept. Upgrade returns whether the hash was actually
// upgraded.
func (u *UserHash) Upgrade(password string) (upgraded bool, err error) {
	if !u.isValidName() {
		return false, fmt.Errorf("whawty.auth.store: username '%s' is invalid", u.user)
	}
	oldLine, _, err := u.readHashLineOf()
	if errors.Is(err, errUserNotFound) {
		return false, fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	} else if err != nil {
		return false, err
	}
	formatID, lastChange, paramID, hashStr, err := parseHashLine(oldLine)
	if err != nil {
		return false, err
	}
	if paramID == u.store.Default {
		return false, nil
	}
	hasher := u.store.Params[paramID]
	if hasher == nil || hasher.GetFormatID() != formatID {
		return false, fmt.Errorf("whawty.auth.store: won't upgrade unsupported hash format '%s' with parameter-set %d", formatID, paramID)
	}
	if ok, _ := hasher.Check(password, hashStr); !ok {
		return false, fmt.Errorf("whawty.auth.store: password of user '%s' has changed, not upgrading", u.user)
	}

	// The password stays the same, so does the time it has been changed.
	newLine, err := u.generateHashLine(password, lastChange)
	if err != nil {
		return false, err
	}

	unlock, err := u.store.lock()
	if err != nil {
		return false, err
	}
	defer unlock()

	format, isAdmin, err := u.locateLocked()
	if err != nil {
		return false, err
	} else if format == formatNone {
		return false, fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}
	// Only write the new hash if nobody changed the hash since we checked the password.
	path := u.hashPath(format, isAdmin)
	if currentLine, err := readHashLine(path); err != nil {
		return false, err
	} else if currentLine != oldLine {
		return false, nil
	}
	if format == formatV2 {
		err = u.store.replaceFile(path, newLine)
	} else {
		err = u.writeHashLine(path, newLine, false)
	}
	return err == nil, err
}

// SetAdmin changes the admin status of user.
func (u *UserHash) SetAdmin(adminState bool) error {
	if !u.isValidName() {
		return fmt.Errorf("whawty.auth.store: username '%s' is invalid", u.user)
	}
	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	format, isAdmin, err := u.locateLocked()
	if err != nil {
		return err
	}
	if format == formatNone {
		return fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}
	if isAdmin == adminState {
		return nil
	}

	if format == formatV2 {
		return u.setAdminFile(adminState)
	}
	if err := os.Rename(u.getFilename(isAdmin), u.getFilename(adminState)); err != nil {
		return err
	}
	return syncDir(u.store.BaseDir)
}

// Remove deletes the user in both store formats. It is not an error if the user does not exist.
func (u *UserHash) Remove() error {
	if !u.isValidName() {
		return fmt.Errorf("whawty.auth.store: username '%s' is invalid", u.user)
	}
	unlock, err := u.store.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if err := u.removeUserDir(); err != nil {
		return err
	}
	for _, isAdmin := range []bool{true, false} {
		if err := os.Remove(u.getFilename(isAdmin)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return syncDir(u.store.BaseDir)
}

// maxHashFileLookups limits how often readHashLineOf() looks for a v1 file of a user.
const maxHashFileLookups = 6

var errUserNotFound = errors.New("whawty.auth.store: user not found")

// readV1HashFile reads the first line of the v1 hash file of user, trying the .admin file first.
func (u *UserHash) readV1HashFile() (line string, isAdmin bool, err error) {
	for _, isAdmin := range []bool{true, false} {
		file, err := os.Open(u.getFilename(isAdmin))
		if err == nil {
			defer file.Close() //nolint:errcheck
			line, err = readHashLineFrom(file)
			return line, isAdmin, err
		}
		if !isNotFound(err) {
			return "", false, err
		}
	}
	return "", false, errUserNotFound
}

// readHashLineOf reads the first line of the hash file of user and whether user is an admin,
// without taking the store lock. Users stored in format v2 take precedence over v1 files.
// It returns errUserNotFound if user does not exist.
//
// Every opened file is a consistent snapshot, since files are never modified in place. Finding
// the file is what can go wrong: SetAdmin() renames v1 files, which may happen between looking
// for the .admin and the .user file, and the migration replaces a v1 file by a user directory,
// which may happen between looking for both formats. The lookup is therefore repeated. A user
// that exists all the time is only missed if it got renamed or migrated between every two
// lookups. Writers hold the store lock and sync the directory, which makes that practically
// impossible.
func (u *UserHash) readHashLineOf() (line string, isAdmin bool, err error) {
	for round := 0; round < maxHashFileLookups/2; round++ {
		if line, isAdmin, err = u.readUserDir(); !errors.Is(err, errUserNotFound) {
			return line, isAdmin, err
		}
		if line, isAdmin, err = u.readV1HashFile(); !errors.Is(err, errUserNotFound) {
			return line, isAdmin, err
		}
	}
	return "", false, errUserNotFound
}

// Exists checks if user exists. It also returns whether user is an admin. This returns true even if
// the user's hash file format is not supported
func (u *UserHash) Exists() (exists bool, isAdmin bool, err error) {
	if !u.isValidName() {
		return false, false, nil
	}
	_, isAdmin, err = u.readHashLineOf()
	if errors.Is(err, errUserNotFound) {
		return false, false, nil
	} else if err != nil {
		return false, false, err
	}
	return true, isAdmin, nil
}

// Authenticate checks the user password. It also returns whether user is an admin, the password is upgradable
// and when the password was last changed.
func (u *UserHash) Authenticate(password string) (isAuthenticated, isAdmin, upgradeable bool, lastchange time.Time, err error) {
	var line string
	if !u.isValidName() {
		// an invalid name is treated exactly like an unknown user
		err = errUserNotFound
	} else {
		line, isAdmin, err = u.readHashLineOf()
	}
	if err != nil && !errors.Is(err, errUserNotFound) {
		return
	} else if err != nil {
		// Spend the same amount of time as for an existing user, so response times don't
		// reveal which users exist.
		if hasher := u.store.Params[u.store.Default]; hasher != nil {
			hasher.Generate(password) //nolint:errcheck
		}
		return false, false, false, time.Unix(0, 0), fmt.Errorf("whawty.auth.store: user '%s' does not exist", u.user)
	}

	var formatID, hashStr string
	var paramID uint
	if formatID, lastchange, paramID, hashStr, err = parseHashLine(line); err != nil {
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
