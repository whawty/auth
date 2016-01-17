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

// Package whawty.store implements a simple storage backend for whawty password
// hash files. The schema of the whawty password store can be found in the doc
// directory.
// If the environment contains the variable WHAWTY_DEBUG logging will be enabled.
// By default whawty doesn't log anything.
package whawty

import (
	"io/ioutil"
	"log"
	"os"
)

var (
	wl = log.New(ioutil.Discard, "[whawty]\t", log.LstdFlags)
)

func init() {
	if _, exists := os.LookupEnv("WHAWTY_DEBUG"); exists {
		wl.SetOutput(os.Stderr)
	}
}

// Store contains all values needed to run the server. Use NewStore to create it.
type Store struct {
	basedir string
}

// NewStore creates a new whawty store using basedir as base directory.
func NewStore(basedir string) (s *Store) {
	s = &Store{}
	s.basedir = basedir
	return s
}

// Init initalizes the store by creating a password file for an admin user.
func (s *Store) Init(admin, password string) (err error) {
	return
}

// AddUser adds user to the store. It is an error if the user already exists.
func (s *Store) AddUser(user, password string, is_admin bool) (err error) {
	return
}

// UpdateUser changes the password and admin status of user. It is an error
// if the user does not exist.
func (s *Store) UpdateUser(user, password string, is_admin bool) (err error) {
	return
}

// AddOrUpdateUser changes the password and admin status of an already exisitng
// user. If the user does not exist yet it will get created.
func (s *Store) AddOrUpdateUser(user, password string, is_admin bool) (err error) {
	return
}

// RemoveUser removes user from the store.
func (s *Store) RemoveUser(user string) {
	return
}

// Exists checks if user exists.
func (s *Store) Exists(user string) (is_admin bool) {
	return
}

// IsAdmin checks if user exists and is an admin.
func (s *Store) IsAdmin(user string) (is_admin bool, err error) {
	return
}

// Authenticate checks user and password are a valid combination. It also returns
// whether user is an admin.
func (s *Store) Authenticate(user, password string) (authenticated, is_admin bool, err error) {
	return
}
