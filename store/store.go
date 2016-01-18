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

// Package auth implements a simple storage backend for whawty.auth password
// hash files. The schema of the whawty.auth password store can be found in the
// doc directory.
// If the environment contains the variable WHAWTY_AUTH_DEBUG logging will be enabled.
// By default whawty.auth doesn't log anything.
package auth

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

var (
	wl = log.New(ioutil.Discard, "[whawty.auth]\t", log.LstdFlags)
)

func init() {
	if _, exists := os.LookupEnv("WHAWTY_AUTH_DEBUG"); exists {
		wl.SetOutput(os.Stderr)
	}
}

// Store represents a whawty.auth password hash store. Use NewStore to create it.
type Store struct {
	basedir string
}

// NewStore creates a new whawty.auth store using basedir as base directory.
func NewStore(basedir string) (s *Store) {
	s = &Store{}
	s.basedir = filepath.Clean(basedir)
	return
}

// Init initalizes the store by creating a password file for an admin user.
func (s *Store) Init(admin, password string) (err error) {
	// TODO: implement this
	return
}

// Check tests if the directory is a valid whawty.auth base directory.
func (s *Store) Check() (ok bool, err error) {
	// TODO: implement this
	return
}

// AddUser adds user to the store. It is an error if the user already exists.
func (s *Store) AddUser(user, password string, isAdmin bool) (err error) {
	// TODO: implement this
	return
}

// UpdateUser changes the password and admin status of user. It is an error
// if the user does not exist.
func (s *Store) UpdateUser(user, password string, isAdmin bool) (err error) {
	// TODO: implement this
	return
}

// AddOrUpdateUser changes the password and admin status of an already exisitng
// user. If the user does not exist yet it will get created.
func (s *Store) AddOrUpdateUser(user, password string, isAdmin bool) (err error) {
	// TODO: implement this
	return
}

// RemoveUser removes user from the store.
func (s *Store) RemoveUser(user string) {
	NewUserHash(s.basedir, user).Remove()
	return
}

// UserList is the return value of List(). The key of the map is the username
// and the value is true if the user is an admin.
type UserList map[string]bool

// List returns a list of all users in the store.
func (s *Store) List() (list UserList) {
	list = make(UserList)
	// TODO: implement this
	return
}

// Exists checks if user exists.
func (s *Store) Exists(user string) (isAdmin bool, err error) {
	return NewUserHash(s.basedir, user).Exists()
}

// IsAdmin checks if user exists and is an admin.
func (s *Store) IsAdmin(user string) (isAdmin bool, err error) {
	return NewUserHash(s.basedir, user).IsAdmin()
}

// Authenticate checks user and password are a valid combination. It also returns
// whether user is an admin.
func (s *Store) Authenticate(user, password string) (isAuthenticated, isAdmin bool, err error) {
	// TODO: implement this
	return
}
