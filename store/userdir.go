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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// pathExists is like fileExists but treats ENOTDIR as not existing.
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return true, err
}

// isDirPath returns whether path is a directory. It doesn't follow a symlink at path.
func isDirPath(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}

type userFormat int

const (
	formatNone userFormat = iota
	formatV1
	formatV2
)

// locateLocked finds the hash of user. A user stored in format v2 takes precedence over v1
// files of the same user. The caller must hold the store lock.
func (u *UserHash) locateLocked() (format userFormat, isAdmin bool, err error) {
	if exists, err := pathExists(filepath.Join(u.getDir(), hashFile)); err != nil {
		return formatNone, false, err
	} else if exists {
		isAdmin, err := pathExists(filepath.Join(u.getDir(), adminFile))
		return formatV2, isAdmin, err
	}
	exists, isAdmin, err := u.existsLocked()
	if err != nil {
		return formatNone, false, err
	} else if exists {
		return formatV1, isAdmin, nil
	}
	return formatNone, false, nil
}

// hashPath returns the file holding the hash line of user.
func (u *UserHash) hashPath(format userFormat, isAdmin bool) string {
	if format == formatV2 {
		return filepath.Join(u.getDir(), hashFile)
	}
	return u.getFilename(isAdmin)
}

// hasV1Users returns whether the store holds users in format v1. As long as it does, new users
// are added in format v1 too. The caller must hold the store lock.
func (d *Dir) hasV1Users() (bool, error) {
	dir, err := openDir(d.BaseDir)
	if err != nil {
		return false, err
	}
	defer dir.Close() //nolint:errcheck
	entries, err := dir.ReadDir(0)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if isDir, err := isDirEntry(dir.Name(), entry); err != nil || isDir {
			continue
		}
		if valid, _, _, err := checkUserFile(entry.Name()); err == nil && valid {
			return true, nil
		}
	}
	return false, nil
}

// writeNewFile creates path, which must not exist yet, with content and syncs it to disk.
func writeNewFile(path, content string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck
	if _, err := io.WriteString(file, content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

// replaceFile atomically replaces path by a file with content. The caller must hold the store lock.
func (d *Dir) replaceFile(path, content string) error {
	tmp, err := d.getTempFile()
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	defer tmp.Close()           //nolint:errcheck

	if _, err := io.WriteString(tmp, content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// addUserDir adds user in format v2. The directory is built in .tmp and renamed into place, so
// the user appears complete. The caller must hold the store lock.
func (u *UserHash) addUserDir(hashLine string, isAdmin bool) error {
	tmpBase := filepath.Join(u.store.BaseDir, tmpDir)
	if err := os.MkdirAll(tmpBase, 0700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(tmpBase, "user-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp) //nolint:errcheck

	if err := writeNewFile(filepath.Join(tmp, hashFile), hashLine); err != nil {
		return err
	}
	if isAdmin {
		if err := writeNewFile(filepath.Join(tmp, adminFile), ""); err != nil {
			return err
		}
	}
	if err := syncDir(tmp); err != nil {
		return err
	}

	// A directory without hash file is not a user, but rename() would replace it if it
	// was empty, or fail if not.
	if exists, err := pathExists(u.getDir()); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("whawty.auth.store: '%s' already exists", u.getDir())
	}
	if err := os.Rename(tmp, u.getDir()); err != nil {
		return err
	}
	return syncDir(u.store.BaseDir)
}

// setAdminFile creates or removes the admin file of user stored in format v2. The caller must
// hold the store lock.
func (u *UserHash) setAdminFile(adminState bool) error {
	path := filepath.Join(u.getDir(), adminFile)
	if adminState {
		if err := writeNewFile(path, ""); err != nil && !os.IsExist(err) {
			return err
		}
	} else {
		if err := os.Remove(path); err != nil && !isNotFound(err) {
			return err
		}
	}
	return syncDir(u.getDir())
}

// removeUserDir removes the directory of user, if there is one. It is renamed into .tmp first,
// so the user disappears at once. The caller must hold the store lock.
func (u *UserHash) removeUserDir() error {
	// The v1 file of another user may have this name, e.g. 'alice.user' of user 'alice'.
	if isDir, err := isDirPath(u.getDir()); err != nil || !isDir {
		return err
	}
	tmpBase := filepath.Join(u.store.BaseDir, tmpDir)
	if err := os.MkdirAll(tmpBase, 0700); err != nil {
		return err
	}
	holder, err := os.MkdirTemp(tmpBase, "removed-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(holder) //nolint:errcheck
	if err := os.Rename(u.getDir(), filepath.Join(holder, "user")); err != nil {
		return err
	}
	if err := syncDir(u.store.BaseDir); err != nil {
		return err
	}
	return os.RemoveAll(holder)
}
