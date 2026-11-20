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
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// v1Users returns the users stored in format v1, and whether they are admins. Files with
// invalid user names and files that aren't user files are skipped. It is an error if a
// user has both an .admin and a .user file. The caller must hold the store lock.
func (d *Dir) v1Users() (map[string]bool, error) {
	dir, err := openDir(d.BaseDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close() //nolint:errcheck
	entries, err := dir.ReadDir(0)
	if err != nil {
		return nil, err
	}

	users := make(map[string]bool)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if isDir, err := isDirEntry(dir.Name(), entry); err != nil {
			return nil, err
		} else if isDir {
			continue
		}
		valid, user, isAdmin, err := checkUserFile(entry.Name())
		if err != nil || !valid {
			wl.Printf("migrate: ignoring file '%s'", entry.Name())
			continue
		}
		if _, exists := users[user]; exists {
			return nil, fmt.Errorf("whawty.auth.store: both '%s' and '%s' exist", user+adminExt, user+userExt)
		}
		users[user] = isAdmin
	}
	return users, nil
}

// hasAuxData returns whether the v1 file has anything but white space after its first line.
func hasAuxData(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close() //nolint:errcheck

	reader := bufio.NewReader(file)
	if _, err := reader.ReadString('\n'); err != nil {
		if err == io.EOF {
			return false, nil
		}
		return false, err
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(rest)) != "", nil
}

// Migrate converts all users stored in format v1 to format v2 and returns their names. It holds
// the store lock while it runs and converts one user at a time: the directory of the user is
// built in .tmp and renamed into place, then the v1 file is removed. Readers therefore find
// every user in at least one of the formats. If a user already has a directory, which is left
// over by an interrupted migration, it takes precedence and only the v1 file gets removed, so
// running Migrate again completes an interrupted migration.
//
// User names may contain dots, so the directory of user 'alice.user' has the name of the v1 file
// of user 'alice'. Users are therefore converted in order of the length of their names, which
// removes such files before their name is needed for a directory.
//
// Users with auxiliary data in their v1 file can't be converted, since format v2 has no place
// for it. In this case, and for users with both an .admin and a .user file, Migrate changes
// nothing and returns an error.
func (d *Dir) Migrate() (migrated []string, err error) {
	unlock, err := d.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	users, err := d.v1Users()
	if err != nil {
		return nil, err
	}
	var names, withAuxData []string
	for name, isAdmin := range users {
		names = append(names, name)
		if aux, err := hasAuxData(NewUserHash(d, name).getFilename(isAdmin)); err != nil {
			return nil, err
		} else if aux {
			withAuxData = append(withAuxData, name)
		}
	}
	if len(withAuxData) > 0 {
		sort.Strings(withAuxData)
		return nil, fmt.Errorf("whawty.auth.store: these users have auxiliary data in their v1 file, which format v2 can't hold: %s", strings.Join(withAuxData, ", "))
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})

	for _, name := range names {
		u := NewUserHash(d, name)
		filename := u.getFilename(users[name])
		if converted, err := pathExists(u.hashPath(formatV2, false)); err != nil {
			return migrated, err
		} else if !converted {
			line, err := readHashLine(filename)
			if err != nil {
				return migrated, err
			}
			if err := u.addUserDir(line, users[name]); err != nil {
				return migrated, fmt.Errorf("whawty.auth.store: migrating '%s' failed: %v", name, err)
			}
		}
		if err := os.Remove(filename); err != nil {
			return migrated, err
		}
		if err := syncDir(d.BaseDir); err != nil {
			return migrated, err
		}
		migrated = append(migrated, name)
	}
	return migrated, nil
}
