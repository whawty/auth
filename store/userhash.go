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
// * Neither the name of whawty nor the names of its
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

package whawty

import (
	"io"
	"os"
	"path/filepath"
)

// UserHash is the representation of a single user hash file inside the store.
// Use NewUserHash to create it.
type UserHash struct {
	basedir string
	user    string
}

// NewUserHash creates a new whawty UserHash fo user inside basedir.
func NewUserHash(basedir, user string) (u *UserHash) {
	u = &UserHash{}
	u.basedir = basedir
	u.user = user
	return
}

// Add creates the hash file. It is an error if the user already exists.
func (u *UserHash) Add(password string, isAdmin bool) (err error) {
	filename := filepath.Join(u.basedir, u.user)
	if isAdmin {
		filename += ".admin"
	} else {
		filename += ".user"
	}
	var file *os.File
	if file, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600); err != nil {
		return
	}
	defer file.Close()
	var hash string
	if hash, err = CalcHash(password); err != nil {
		return
	}
	if _, err = io.WriteString(file, hash+"\n"); err != nil {
		return // TODO: retry if write was short
	}
	return
}

// Update changes the password and admin status of user.
func (u *UserHash) Update(password string, isAdmin bool) (err error) {
	// TODO: implement this
	return
}

// Remove deletes hash file.
func (u *UserHash) Remove() {
	filename := filepath.Join(u.basedir, u.user)
	os.Remove(filename + ".admin")
	os.Remove(filename + ".user")
	return
}

// IsFormatSupported checks if the format of the hash file is supported
func (u *UserHash) IsFormatSupported() (ok bool, err error) {
	// TODO: implement this
	return
}

// Exists checks if user exists.
func (u *UserHash) Exists() (isAdmin bool, err error) {
	// TODO: implement this
	return
}

// IsAdmin checks if user exists and is an admin.
func (u *UserHash) IsAdmin() (isAdmin bool, err error) {
	// TODO: implement this
	return
}
