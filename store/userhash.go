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

// Check if the format of the hash file is supported
func (s *UserHash) IsFormatSupported() (ok bool, err error) {
	return
}

// Add creates the hash file. It is an error if the user already exists.
func (s *UserHash) Add(password string, isAdmin bool) (err error) {
	return
}

// Update changes the password and admin status of user.
func (s *UserHash) Update(password string, isAdmin bool) (err error) {
	return
}

// Remove deletes hash file.
func (s *UserHash) Remove() {
	return
}

// Exists checks if user exists.
func (s *UserHash) Exists() (isAdmin bool, err error) {
	return
}

// IsAdmin checks if user exists and is an admin.
func (s *UserHash) IsAdmin() (isAdmin bool, err error) {
	return
}