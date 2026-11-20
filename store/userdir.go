//
// Copyright (c) 2026 whawty contributors (see AUTHORS file)
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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// In store format v2 every user is a directory named like the user. A user exists exactly when
// this directory contains the file 'hash', which holds the same line as the first line of a v1
// user file. The empty file 'admin' marks admins. Other files hold data of extensions and are
// ignored by agents that don't know them, as are hidden files.
const (
	hashFile  string = "hash"
	adminFile string = "admin"
)

// isNotFound returns true for errors meaning that a path doesn't exist. Looking for
// '<user>/hash' while '<user>' is a file, e.g. the v1 file of another user, returns ENOTDIR.
func isNotFound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func (u *UserHash) getDir() string {
	return filepath.Join(u.store.BaseDir, u.user)
}

// readUserDir reads the hash line and the admin status of user stored in format v2. It doesn't
// take the store lock: the user directory is opened once and both files are read relative to
// it, so a user that gets removed and added again in the meantime is never mixed up with the
// new one. Every file is replaced atomically. It returns errUserNotFound if there is no user
// directory or it doesn't contain a hash file, which happens on replicas while rsync
// transfers a new user.
func (u *UserHash) readUserDir() (line string, isAdmin bool, err error) {
	root, err := os.OpenRoot(u.getDir())
	if err != nil {
		if isNotFound(err) {
			return "", false, errUserNotFound
		}
		// os.OpenRoot() doesn't use ENOTDIR if the path is not a directory
		if info, serr := os.Stat(u.getDir()); isNotFound(serr) || (serr == nil && !info.IsDir()) {
			return "", false, errUserNotFound
		}
		return "", false, err
	}
	defer root.Close() //nolint:errcheck

	file, err := root.Open(hashFile)
	if err != nil {
		if isNotFound(err) {
			return "", false, errUserNotFound
		}
		return "", false, err
	}
	defer file.Close() //nolint:errcheck
	if line, err = readHashLineFrom(file); err != nil {
		return "", false, err
	}

	if _, err = root.Stat(adminFile); err == nil {
		isAdmin = true
	} else if !isNotFound(err) {
		return "", false, err
	}
	return line, isAdmin, nil
}

// isDirEntry returns whether the entry name of directory dir is a directory, following symlinks.
func isDirEntry(dir string, entry fs.DirEntry) (bool, error) {
	if entry.Type()&fs.ModeSymlink == 0 {
		return entry.IsDir(), nil
	}
	info, err := os.Stat(filepath.Join(dir, entry.Name()))
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}
